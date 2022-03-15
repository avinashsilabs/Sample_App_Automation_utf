import time
import pytest
from utf_wiseconnect.devices.rs911x import RS9116CoexMode
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.interfaces.bluetooth.hid_recorder import HidRecorder
from utf_wiseconnect.interfaces.cli.rs_at_commands import RSATCommands
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth.bluetooth_interface import (
    BluetoothInterface,
    BTRole,
    BTProfile,
    BTEvents,
)

def logger():
    return get_logger(__name__)

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
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.Bluetooth,
        }
    )
]
@pytest.mark.parametrize("enable_ssp", [True])
def test_hid_conn_in_device_role_C20017(bt_dut, bt_client, enable_ssp):
    with TimeMeasurer() as t:

        logger().info("configuring dut for hid slave role with sdp config data....")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=enable_ssp)
        assert bt_dut_address is not None
        logger().info(f'bt dut address {bt_dut_address}')

        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address is not None
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

    logger().info(f"test completed in {t.duration} seconds")

@pytest.mark.parametrize("enable_ssp", [True])
def test_Interrupt_data_after_hid_conn_C20021(bt_dut, bt_client, enable_ssp):
    with TimeMeasurer() as t:
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=enable_ssp)
        assert bt_dut_address is not None
        logger().info(f'bt dut address {bt_dut_address}')

        # Begin Scanning for BLE devices
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address is not None
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
            assert hid_logs[i] == test_data[i]

        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)
    logger().info(f"test completed in {t.duration} seconds")

def test_set_local_cod_C20023(bt_dut, bt_client):
    logger().info("set bt profile....")
    bt_dut.interfaces.bluetooth.bt_set_profile(profile="40")

    logger().info("set sdp config....")
    bt_dut.interfaces.bluetooth.bt_hid_send_sdp_config()

    logger().info("configure bt class.... ")
    bt_dut.interfaces.bluetooth.bt_set_class(cod="002560")

    logger().info("configure bt local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name='REDPINE_HID_KEYBOARD')

    logger().info("initializing bt.....")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("get dut bt address.....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
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

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address is not None
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
        assert hid_logs[i] == test_data[i]
    logger().info("disconnecting bt hid...")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)

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

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address is not None
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
        assert hid_logs[i] == test_data[i]
    logger().info("disconnecting bt hid...")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)

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

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address is not None
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
        assert hid_logs[i] == test_data[i]
    logger().info("disconnecting bt hid...")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.parametrize("enable_ssp", [True])
def test_hid_conn_send_Interrupt_data_in_ps_3_ulp_mode_C20031(bt_dut, bt_client, enable_ssp):

    logger().info("configuring dut for hid slave role with sdp config data with capability....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=enable_ssp)
    assert bt_dut_address is not None
    logger().info(f'bt dut address {bt_dut_address}')

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address is not None
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

    logger().info("set dut in power save.....")
    bt_dut.interfaces.bluetooth.bt_power_save(3,2)

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i]

@pytest.mark.parametrize("enable_ssp", [True])
def test_hid_conn_disconn_by_Interrupt_ps_3_ulp_mode_C20035(bt_dut, bt_client, enable_ssp):

    logger().info("configuring dut for hid slave role with sdp config data with capability....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=enable_ssp)
    assert bt_dut_address is not None
    logger().info(f'bt dut address {bt_dut_address}')

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address is not None
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

    logger().info("set dut in power save.....")
    bt_dut.interfaces.bluetooth.bt_power_save(3,2)

    with HidRecorder() as hid_recorder:
        for item in test_data:
            logger().info("sending interrupt data at remote window....")
            bt_dut.interfaces.bluetooth.bt_hid_send_interrupt(bt_client_address, data=item)
        hid_logs = hid_recorder.logs()

    assert len(hid_logs) == len(test_data)
    for i in range(len(test_data)):
        assert hid_logs[i] == test_data[i]
    logger().info("disconnecting bt hid...")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.parametrize("enable_ssp", [True])
def test_hid_conn_and_disconn_C20019(bt_dut, bt_client, enable_ssp):

    logger().info("configuring dut for hid slave role with sdp config data....")
    bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=enable_ssp)
    assert bt_dut_address is not None
    logger().info(f'bt dut address {bt_dut_address}')

    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                  pin_code=pin_code)
    assert bt_client_address is not None
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

    logger().info("disconnecting bt hid from device...")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)

@pytest.mark.parametrize("enable_ssp", [True])
def test_hid_disconn_in_device_role_C20018(bt_dut, bt_client, enable_ssp):
    for i in range(0, 8):
        logger().info("configuring dut for hid slave role with sdp config data....")
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_slave_hid(enable_ssp=enable_ssp)
        assert bt_dut_address is not None
        logger().info(f'bt dut address {bt_dut_address}')

        logger().info("initiating scan form remote bt device...")
        bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                          pin_code=pin_code)
        assert bt_client_address is not None
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

        logger().info("disconnecting bt hid from device...")
        bt_client.interfaces.bluetooth.disconnect(bt_dut_address)

def test_hid_connectivity_SSP_with_IO_capa_keyboard_only_C20027(bt_dut, bt_client):

    logger().info("Initializing dut with hid...")
    bt_dut.interfaces.bluetooth.bt_hid_init()

    logger().info("configuring dut local name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name="bt_local_name")
    bt_dut.interfaces.bluetooth.bt_set_slave_role()

    logger().info("configuring dut with capability....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=2)

    logger().info("configuring dut pin code....")
    pin_code = bt_dut.interfaces.bluetooth.bt_set_pin_code()

    logger().info("fetching dut local address....")
    bt_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()
    logger().info(f'bt dut address {bt_dut_address}')

    # Begin Scanning for BLE devices
    logger().info("initiating scan form remote bt device...")
    bt_client_address = bt_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address,
                                                                      pin_code=pin_code)
    assert bt_client_address is not None
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
        assert hid_logs[i] == test_data[i]
    logger().info("disconnecting bt hid...")
    bt_client.interfaces.bluetooth.disconnect(bt_dut_address)