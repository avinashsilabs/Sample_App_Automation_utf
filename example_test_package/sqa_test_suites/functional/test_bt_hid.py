import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116ExtCustomFeatureBitMap
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116FeatureBitMap,
    RS9116BTFeatureBitMap
    )

def logger():
    return get_logger(__name__)

#configure this to run the case for no of times in loop
iter_count = 3

#sniff mode inputs
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
        2. Configure dut with the HID parameters and argumets
        3. Initiate Scan, connect and interrupt data between the bt socket
        4. verify the functionality

    Author: RaviNemali
    
    Note: ******** This test plan supports only in AT mode **********
"""


pytestmark = [
    pytest.mark.bt_client("raspi_ble_client"),
    pytest.mark.dut("rs9116"),
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth,
            "features": RS9116FeatureBitMap.OpenMode,
            "tcpip_features": RS9116TCPIPFeatureBitMap.TCPIPBypass,
            "ext_tcpip_features": 0,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
            "ble_features": 0,
            "rejoin_enable":False,
        }
    )
]
def test_hid_conn_in_device_role_C20017(bt_dut, bt_client):
    with TimeMeasurer() as t:

        logger().info("configuring dut for hid slave role with sdp config data....")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=False)
        assert bt_dut_address,"failed to initialise bt in dut"
        logger().info(f'bt dut address {bt_dut_address}')

        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address,"rpi failed to scan dut..."
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

def test_interrupt_data_after_hid_conn_C20021(bt_dut, bt_client):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=False)
        assert bt_dut_address,"bt initialization failed in dut"
        logger().info(f'bt dut address {bt_dut_address}')

        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address,"failed to scan..."
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
            connected = bt_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
            assert connected, "unable to connect bt device"
            logger().info(f'device connection state is {connected}')

        with HidRecorder() as hid_recorder:
            for item in test_data:
                bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data)
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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

def test_set_local_cod_C20023_class_002560(bt_dut, bt_client):
    logger().info("set bt profile....")
    bt_dut.interfaces.bluetooth.bt_set_profile(profile="40")

    logger().info("set sdp config....")
    bt_dut.interfaces.bluetooth.bt_hid_send_sdp_config()

    logger().info("configure bt class.... ")
    bt_dut.interfaces.bluetooth.bt_set_class(cod="002560")

    logger().info("get cod")
    bt_dut.interfaces.bluetooth.bt_get_class()

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='REDPINE_HID_KEYBOARD')

    logger().info("initializing bt.....")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()
    bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to scan dut"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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

def test_set_local_cod_C20023_class_002540(bt_dut, bt_client):
    logger().info("set bt profile....")
    bt_dut.interfaces.bluetooth.bt_set_profile(profile="40")

    logger().info("set sdp config....")
    bt_dut.interfaces.bluetooth.bt_hid_send_sdp_config()

    logger().info("configure bt class.... ")
    bt_dut.interfaces.bluetooth.bt_set_class(cod="002540")

    logger().info("get cod")
    bt_dut.interfaces.bluetooth.bt_get_class()

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='REDPINE_HID_KEYBOARD')

    logger().info("initializing bt.....")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()
    bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate scan in remote device"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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

def test_set_local_cod_C20023_class_002580(bt_dut, bt_client):
    logger().info("set bt profile....")
    bt_dut.interfaces.bluetooth.bt_set_profile(profile="40")

    logger().info("set sdp config....")
    bt_dut.interfaces.bluetooth.bt_hid_send_sdp_config()

    logger().info("configure bt class.... ")
    bt_dut.interfaces.bluetooth.bt_set_class(cod="002580")

    logger().info("get cod")
    bt_dut.interfaces.bluetooth.bt_get_class()

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='REDPINE_HID_KEYBOARD')

    logger().info("initializing bt.....")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()
    bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address,"failed to initiate scan in remote device"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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

def test_hid_connectivity_SSP_with_IO_capa_Display_only_C20025(bt_dut, bt_client):

    logger().info("Initializing dut with hid...")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_hid_io_capability")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    logger().info("configuring dut pin code....")
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address,"failed to initiate scan in remote device"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

def test_hid_connectivity_SSP_with_IO_capa_Display_yes_no_C20026(bt_dut, bt_client):

    logger().info("Initializing dut with hid...")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_local_name")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=1)

    logger().info("configuring dut pin code....")
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address,"failed to initiate scan in remote device"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

def test_hid_connectivity_SSP_with_IO_capa_no_input_output_C20028(bt_dut, bt_client):

    logger().info("Initializing dut with hid...")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_local_name")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=3)

    logger().info("configuring dut pin code....")
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address,"failed to initiate scan in remote device"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"
    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

def test_hid_conn_send_Interrupt_data_in_ps_3_ulp_mode_C20031(bt_dut, bt_client):
    logger().info("configuring dut for hid slave role with sdp config data with capability....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=True)
    assert bt_dut_address,"failed to initiate bt in dut"
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address,"failed to initiate scan in remote device"
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
    bt_dut.interfaces.bluetooth.power_save(3,2)
    logger().info("bt power save configuration success")

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"

    time.sleep(60)

    logger().info("fetching the connection status after 60 secs of sleep")
    connected = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
    assert connected == 1, "dut is disconnected"
    logger().info(f"connection status :{connected}")

    logger().info("disconnecting from bt device")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    bt_client.interfaces.bluetooth.close()
    time.sleep(5)

def test_hid_conn_and_disconn_C20019(bt_dut, bt_client):

        logger().info("configuring dut for hid slave role with sdp config data....")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=True)
        assert bt_dut_address, "failed to initiate bt on dut"
        logger().info(f'bt dut address {bt_dut_address}')

        for count in range(0, iter_count):
            logger().info(f"******************* iteration {count}  ********************* ")
            logger().info("initiating scan form remote bt device...")
            bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                  pin_code=pin_code)
            assert bt_client_address,"failed to initiate bt on client"
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
                result = bt_client.interfaces.bluetooth.get_connection_status(dev_addr=bt_dut_address)
                assert result == 1, "dut is disconnected"
                logger().info(f"connection status :{result}")

                logger().info("disconnecting from bt device")
                bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
                time.sleep(5)
                bt_client.interfaces.bluetooth.close()
                logger().info(f"******************* iteration {count} completed ********************* ")
        time.sleep(5)

def test_hid_disconn_in_device_role_C20018(bt_dut, bt_client):
        logger().info("configuring dut for hid slave role with sdp config data....")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=True)
        assert bt_dut_address,"failed to initialize bt in dut"
        logger().info(f'bt dut address {bt_dut_address}')

        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address,"failed to initialize scan in remote device"
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

def test_hid_connectivity_SSP_with_IO_capa_keyboard_only_C20027(bt_dut, bt_client):
    pin_code = "123456"
    logger().info("Initializing dut with hid...")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_local_name")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=2)

    logger().info("configuring dut pin code....")
    bt_dut.interfaces.bluetooth.bt_set_pin_code(pin_code)

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code, capability="KeyboardOnly")
    assert bt_client_address,"failed to initialize scan in remote device"
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

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"
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

def test_hid_conn_send_Interrupt_data_in_ps_3_lp_mode_C20030(bt_dut, bt_client):
    logger().info("configuring dut for hid slave role with sdp config data with capability....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=True)
    assert bt_dut_address ,"failed to initialize bt dut"
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address ,"bt client setup failed"
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
    bt_dut.interfaces.bluetooth.power_save(3,1)
    time.sleep(15)
    logger().info("bt power save configuration success")

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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

def test_hid_conn_send_Interrupt_data_in_ps_3_lp_mode_C20034(bt_dut, bt_client):

    logger().info("configuring dut for hid slave role with sdp config data with capability....")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_local_name")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    logger().info("configuring dut pin code....")
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
        assert bt_client_address,"bt client setup failed"
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
        bt_dut.interfaces.bluetooth.power_save(3,1)
        logger().info("bt power save configuration success")

        with HidRecorder() as hid_recorder:
            for item in test_data:
                logger().info("sending interrupt data at remote window....")
                bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data)
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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

def test_hid_conn_send_Interrupt_data_in_ps_3_ulp_mode_C20035(bt_dut, bt_client):

    logger().info("configuring dut for hid slave role with sdp config data with capability....")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_local_name")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    logger().info("configuring dut pin code....")
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    for count in range(0, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
        assert bt_client_address,"bt client setup failed"
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
        bt_dut.interfaces.bluetooth.power_save(3,2)
        logger().info("bt power save configuration success")

        with HidRecorder() as hid_recorder:
            for item in test_data:
                logger().info("sending interrupt data at remote window....")
                bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
            hid_logs = hid_recorder.logs()

        assert len(hid_logs) == len(test_data)
        for i in range(len(test_data)):
            assert hid_logs[i] == test_data[i],"hid data and test data is not same"

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