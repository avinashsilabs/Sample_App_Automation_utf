import time
from datetime import datetime, timedelta
import pytest
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
from utf.interfaces.bluetooth.bluetooth_interface import BTProfile
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116BTFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116PowerSaveProcedureTypes,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ConfigFeatureBitMap
)
from utf_wiseconnect.devices.rs911x import RS9116ExtCustomFeatureBitMap


def logger():
    return get_logger(__name__)


# configure this to run the case for no of times in loop
iter_count = 3

# sniff mode inputs
SniffMaxIntr = 192
SniffMinIntr = 160
SniffAttempt = 4
sniffTimeout = 2

test_data = ["9,01,00,00,04,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00",
             "9,01,00,00,05,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00",
             "9,01,02,00,04,00,00,00,00,00", "9,01,02,00,00,00,00,00,00,00",
             "9,01,02,00,05,00,00,00,00,00", "9,01,02,00,00,00,00,00,00,00",
             "9,01,00,00,2e,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00",
             "9,01,00,00,3a,00,00,00,00,00", "9,01,00,00,00,00,00,00,00,00"]

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex, Bluetooth mode
        2. Configure dut with the HID parameters and arguments
        3. Initiate Scan, connect and interrupt data between the bt socket
        4. verify the functionality

    Author: RaviNemali/Harshitha

    Note: ******** This test plan supports only in AT mode **********
"""

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20017')
def test_hid_conn_in_device_role_c20017(bt_dut, bt_client):
    with TimeMeasurer() as t:

        logger().info("configuring dut for hid slave role with sdp config data....")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(enable_ssp=False)
        assert bt_dut_address, "failed to initialise bt in dut"
        logger().info(f'bt dut address {bt_dut_address}')

        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address, "rpi failed to scan dut..."
        logger().info(f'bt client address {bt_client_address}')

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break
        logger().info("stop scanning.....")
        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "unable to scan device"

        with bt_dut.interfaces.bluetooth.run_bt_task():
            logger().info("connecting to remote bt device....")
            connected = bt_client.interfaces.bluetooth.connect(bt_dut_address)
            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')
            time.sleep(60)

            logger().info("fetching the connection status after 60 secs of sleep")
            connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
            assert connected == 1, "dut is disconnected"
            logger().info(f"connection status :{connected}")

            time.sleep(10)
            logger().info("disconnecting from bt device")
            bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
            bt_client.interfaces.bluetooth.close()
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20021')
def test_interrupt_data_after_hid_conn_c20021(bt_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(enable_ssp=False)
        assert bt_dut_address, "bt initialization failed in dut"
        logger().info(f'bt dut address {bt_dut_address}')

        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address, "failed to scan..."
        logger().info(f'bt client address {bt_client_address}')

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break

        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "unable to scan device"

        with bt_dut.interfaces.bluetooth.run_bt_task():
            connected = bt_client.interfaces.bluetooth.connect(bt_dut_address)
            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')

        with HidRecorder() as hid_recorder:
            for item in test_data:
                bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i], "hid data and test data is not same"

        time.sleep(60)

        logger().info("fetching the connection status after 60 secs of sleep")
        connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
        assert connected == 1, "dut is disconnected"
        logger().info(f"connection status :{connected}")

        logger().info("disconnecting from bt device")
        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(5)
        bt_client.interfaces.bluetooth.close()
        time.sleep(5)
    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C109698')
def test_set_local_cod_class_002560_c109698(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='REDPINE_HID_KEYBOARD')
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to scan dut"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    assert device_found, "unable to scan dut"

    logger().info("stop scanning.....")
    bt_client.interfaces.bluetooth.stop_scanning()

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C109697')
def test_set_local_cod_class_002540_c109697(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        cod="002540", bt_local_name='REDPINE_HID_KEYBOARD')
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stop scanning.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan dut"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20023')
def test_set_local_cod_class_002580_c20023(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        cod="002580", bt_local_name='REDPINE_HID_KEYBOARD')
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stop scanning.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan dut"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20025')
def test_hid_connectivity_ssp_with_io_capa_display_only_c20025(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='bt_hid_io_capability', pair_mode=1, capability=0)
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect to bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20026')
def test_hid_connectivity_ssp_with_io_capa_display_yes_no_c20026(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='bt_local_name', pair_mode=1, capability=1)
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20028')
def test_hid_connectivity_ssp_with_io_capa_no_input_output_c20028(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='bt_local_name', pair_mode=1, capability=3)
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20031')
def test_hid_conn_send_interrupt_data_in_ps_3_ulp_mode_c20031(bt_dut, bt_client):
    # Set the device's local name
    logger().info("setting local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name("rs911x_bt_hid")

    # Set the local COD (Class of Device)
    logger().info("setting local COD....")
    bt_dut.interfaces.bluetooth.bt_set_class(cod="002560")

    # Set the device in HID profile mode
    logger().info("setting HID profile mode....")
    bt_dut.interfaces.bluetooth.bt_set_profile(profile="40")
    bt_dut.interfaces.bluetooth.bt_set_profile_mode(BTProfile.HID)

    # Set the SDP config to Keyboard service
    logger().info("sending HID SDP config (Keyboard service)....")
    bt_dut.interfaces.bluetooth.bt_hid_send_sdp_config()

    # Set SSP mode (pair_mode=1, capability=3 i.e. NoInputNoOutput)
    logger().info("setting SSP mode....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=3)

    # Set the device in discoverable mode
    logger().info("setting discoverable mode....")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    # Set the device in connectable mode
    logger().info("setting connectable mode....")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    # Get DUT address
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    assert bt_dut_address, "failed to get bt dut address"
    logger().info(f'bt dut address {bt_dut_address}')
    pin_code = "4321"

    # Scan for DUT from remote device
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    logger().info("enabling sniff mode")
    bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                               SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                               sniffTimeout=sniffTimeout)

    time.sleep(5)
    logger().info("set dut in power save.....")
    bt_dut.interfaces.bluetooth.power_save(3, 2)
    logger().info("bt power save configuration success")

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20019')
def test_hid_conn_and_disconn_c20019(bt_dut, bt_client):
    # Set the device's local name
    logger().info("setting local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name("rs911x_bt_hid")

    # Set the local COD (Class of Device)
    logger().info("setting local COD....")
    bt_dut.interfaces.bluetooth.bt_set_class(cod="002560")

    # Set the device in HID profile mode
    logger().info("setting HID profile mode....")
    bt_dut.interfaces.bluetooth.bt_set_profile(profile="40")
    bt_dut.interfaces.bluetooth.bt_set_profile_mode(BTProfile.HID)

    # Set the SDP config to Keyboard service
    logger().info("sending HID SDP config (Keyboard service)....")
    bt_dut.interfaces.bluetooth.bt_hid_send_sdp_config()

    # Set PIN code for legacy pairing
    logger().info("setting pin code....")
    bt_dut.interfaces.bluetooth.bt_set_pin_code(pin_code="4321")

    # Set the device in discoverable mode
    logger().info("setting discoverable mode....")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    # Set the device in connectable mode
    logger().info("setting connectable mode....")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    # Get DUT address
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    assert bt_dut_address, "failed to get bt dut address"
    logger().info(f'bt dut address {bt_dut_address}')
    pin_code = "4321"

    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address, "failed to initiate bt on client"
        logger().info(f'bt client address {bt_client_address}')

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break

        logger().info("stopping scan.....")
        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "unable to scan device"

        with bt_dut.interfaces.bluetooth.run_bt_task():
            logger().info("connecting to remote bt device....")
            connected = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                try:
                    status = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
                    if status == 1:
                        connected = True
                        break
                except Exception:
                    pass
                time.sleep(2)

            if not connected:
                try:
                    connected = bt_client.interfaces.bluetooth.connect(bt_dut_address)
                except Exception as e:
                    logger().info(f"connect() raised: {e}, checking connection status...")
                    time.sleep(5)
                    status = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
                    connected = (status == 1)

            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')

            time.sleep(60)
            logger().info("fetching the connection status after 60 secs of sleep")
            result = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
            assert result == 1, "dut is disconnected"
            logger().info(f"connection status :{result}")

            logger().info("disconnecting from bt device")
            bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(5)
            bt_client.interfaces.bluetooth.close()
            logger().info(f"******************* iteration {count} completed ********************* ")
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20018')
def test_hid_disconn_in_device_role_c20018(bt_dut, bt_client):
    logger().info("configuring dut for hid slave role with sdp config data....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=True)
    assert bt_dut_address, "failed to initialize bt in dut"
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initialize scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        logger().info("connecting to remote bt device....")
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20027')
def test_hid_connectivity_ssp_with_io_capa_keyboard_only_c20027(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='bt_local_name', pair_mode=1, capability=2, bt_pin_code="123456")
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code, capability="KeyboardOnly")
    assert bt_client_address, "failed to initialize scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20035')
def test_hid_conn_send_interrupt_data_in_ps_3_ulp_mode_c20035(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(pair_mode=1, capability=0)
    logger().info("configuring dut local name....")

    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address, "bt client setup failed"
        logger().info(f'bt client address {bt_client_address}')

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break

        logger().info("stopping scan.....")
        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "unable to scan device"

        with bt_dut.interfaces.bluetooth.run_bt_task():
            connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')

        logger().info("enabling sniff mode")
        bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                                   SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                                   sniffTimeout=sniffTimeout)
        time.sleep(5)

        logger().info("set dut in power save.....")
        bt_dut.interfaces.bluetooth.power_save(3, 2)
        logger().info("bt power save configuration success")

        with HidRecorder() as hid_recorder:
            for item in test_data:
                logger().info("sending interrupt data at remote window....")
                bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i], "hid data and test data is not same"

        time.sleep(60)

        logger().info("fetching the connection status after 60 secs of sleep")
        connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
        assert connected == 1, "dut is disconnected"
        logger().info(f"connection status :{connected}")

        logger().info("disconnecting from bt device")
        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
        bt_client.interfaces.bluetooth.close()
        logger().info(f"******************* iteration {count} completed ********************* ")
    time.sleep(10)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20034')
def test_hid_conn_send_interrupt_data_in_ps_3_lp_mode_c20034(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='bt_local_name', pair_mode=1, capability=0)
    logger().info(f'bt dut address {bt_dut_address}')

    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address, "bt client setup failed"
        logger().info(f'bt client address {bt_client_address}')

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break

        logger().info("stopping scan.....")
        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "unable to scan device"

        with bt_dut.interfaces.bluetooth.run_bt_task():
            connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')

        bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                                   SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                                   sniffTimeout=sniffTimeout)
        time.sleep(5)
        logger().info("set dut in power save.....")
        bt_dut.interfaces.bluetooth.power_save(3, 1)
        logger().info("bt power save configuration success")

        with HidRecorder() as hid_recorder:
            for item in test_data:
                logger().info("sending interrupt data at remote window....")
                bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i], "hid data and test data is not same"

        time.sleep(60)

        logger().info("fetching the connection status after 60 secs of sleep")
        connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
        assert connected == 1, "dut is disconnected"
        logger().info(f"connection status :{connected}")

        logger().info("disconnecting from bt device")
        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
        bt_client.interfaces.bluetooth.close()
        logger().info(f"******************* iteration {count} completed ********************* ")
    time.sleep(10)

@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20037')
def test_bt_hid_functionality_in_sniff_mode_c20037(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='REDPINE_HID_KEYBOARD', pair_mode=1, capability=3)

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break
    logger().info("stop scanning.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        logger().info("connecting to remote bt device....")
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    logger().info("enabling sniff mode")
    bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                               SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                               sniffTimeout=sniffTimeout)

    time.sleep(5)
    logger().info("set dut in power save.....")
    bt_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode3,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger().info("bt power save configuration success")

    with HidRecorder() as hid_recorder:
        for item in test_data:
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    logger().info("fetching the rssi value of remote bt device ")
    bt_dut.interfaces.bluetooth.bt_get_rssi(bt_remote_dev_address=bt_client_address)

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()


@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20038')
def test_bt_hid_send_continuous_hid_interrupt_data_c20038(bt_dut, bt_client):
    try:
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
            enable_ssp=True, bt_local_name='REDPINE_HID_KEYBOARD',  pair_mode=1, capability=1)
        assert bt_dut_address, "failed to initialize bt dut"
        logger().info(f'bt dut address {bt_dut_address}')

        # Begin Scanning for BLE devices
        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address, "failed to initiate scan in remote device"
        logger().info(f'bt client address {bt_client_address}')

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
                device_found = True
                break
        logger().info("stop scanning.....")
        bt_client.interfaces.bluetooth.stop_scanning()
        assert device_found, "unable to scan device"

        with bt_dut.interfaces.bluetooth.run_bt_task():
            logger().info("connecting to remote bt device....")
            connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')

        logger().info("enabling sniff mode")
        bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                                   SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                                   sniffTimeout=sniffTimeout)
        time.sleep(5)
        logger().info("set dut in power save.....")
        bt_dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveMode3,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)
        logger().info("bt power save configuration success")
        time.sleep(10)
        # Data will transfer 60 seconds
        end_time = datetime.now() + timedelta(seconds=60)
        while datetime.now() < end_time:
            with HidRecorder() as hid_recorder:
                for item in test_data:
                    bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
                hid_logs = hid_recorder.logs()

            assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
            for i in range(len(test_data)):
                assert hid_logs[i] == test_data[i], "hid data and test data is not same"

        time.sleep(60)
        logger().info("fetching the connection status after 60 secs of sleep")
        connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
        assert connected == 1, "dut is disconnected"
        logger().info(f"connection status :{connected}")

    except Exception as e:
        raise e
    finally:
        logger().info("disconnecting from bt device")
        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(5)
        bt_client.interfaces.bluetooth.close()


@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20030')
def test_hid_conn_send_interrupt_data_in_ps_3_lp_mode_c20030(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        enable_ssp=True, pair_mode=1, capability=1)
    assert bt_dut_address, "failed to initialize bt dut"
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "bt client setup failed"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break

    logger().info("stopping scan.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                               SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                               sniffTimeout=sniffTimeout)
    time.sleep(5)
    logger().info("set dut in power save.....")
    bt_dut.interfaces.bluetooth.power_save(3, 1)
    time.sleep(15)
    logger().info("bt power save configuration success")

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    time.sleep(60)
    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)


@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection | RS9116BTFeatureBitMap.BTSniff,
        "ble_features": 0,
        "rejoin_enable": False,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.test_src_map_id('C20036')
def test_bt_hid_disabling_sniff_feature_c20036(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='REDPINE_HID_KEYBOARD', pair_mode=1, capability=3)
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break
    logger().info("stop scanning.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    with bt_dut.interfaces.bluetooth.run_bt_task():
        logger().info("connecting to remote bt device....")
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    time.sleep(3)

    with HidRecorder() as hid_recorder:
        for item in test_data:
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    logger().info("fetching the rssi value of remote bt device ")
    bt_dut.interfaces.bluetooth.bt_get_rssi(bt_remote_dev_address=bt_client_address)

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()


@pytest.mark.AT
@pytest.mark.bt_client("raspi_ble_client")
@pytest.mark.dut("rs9116")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
        "features": RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "ble_features": 0,
        "rejoin_enable": False,
    }
)
@pytest.mark.test_src_map_id('C20029')
def test_bt_hid_sniff_mode_send_hid_interrupt_data_c20029(bt_dut, bt_client):
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_hid_slave_config(
        bt_local_name='REDPINE_HID_KEYBOARD', pair_mode=1, capability=3)
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("configuring dut in discoverable mode")
    bt_dut.interfaces.bluetooth.bt_start_discoverable()

    logger().info("configuring dur in connectable mode")
    bt_dut.interfaces.bluetooth.bt_set_connectable()

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address, "failed to initiate scan in remote device"
    logger().info(f'bt client address {bt_client_address}')

    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        if bt_dut_address in bt_client.interfaces.bluetooth.get_devices():
            device_found = True
            break
    logger().info("stop scanning.....")
    bt_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "unable to scan device"

    time.sleep(3)

    with bt_dut.interfaces.bluetooth.run_bt_task():
        logger().info("connecting to remote bt device....")
        connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        assert connected, "unable to connect bt device"
        logger().info(f'device connection state is {connected}')

    logger().info("enabling sniff mode")
    bt_dut.interfaces.bluetooth.set_sniff_mode(bt_remote_dev_address=bt_client_address, SniffMaxIntr=SniffMaxIntr,
                                               SniffMinIntr=SniffMinIntr, SniffAttempt=SniffAttempt,
                                               sniffTimeout=sniffTimeout)
    time.sleep(3)

    with HidRecorder() as hid_recorder:
        for item in test_data:
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data), "hid data and test data length is not matched"
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i], "hid data and test data is not same"

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(5)
    bt_client.interfaces.bluetooth.close()
