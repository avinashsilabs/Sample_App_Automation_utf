import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BTSocketRole
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
import time
from devices.rs911x import RS9116AsyncEventType

""" Test-Plan:BT_GAP
    Test-Author:N.Hari Bhargav   
    Test Steps:
        1. Initiates the DUT in Coex wlan and DualBluetoothBLE mode
        2. Configures the remote device in Discovery Mode
        3. DUT initiates the inquiry in Master mode
        4. Fetch the Remote device RSSI, COD, Name, Inquiry types in the inquiry results 
    Setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        }
    )
]


def logger():
    return get_logger(__name__)

def test_bt_inquiry_rssi_C19981(wifi_dut, bt_client):
    inq_type = 1
    duration = 10000
    max_no_dev = 10
    found = 0
    cod = '203040'
    event_data = ''
    with TimeMeasurer() as t:
        # Configure Raspberry pi in slave mode
        bt_client_address = bt_client.interfaces.bluetooth.start_slave()
        assert bt_client_address is not None
        logger().info(f"Raspberry pi BD address {bt_client_address}")
        # Set COD to Raspberry Pi device
        logger().info(f"Set COD to Raspberry pi device")
        bt_client.interfaces.bluetooth.bt_adapter.set_class(cod)

        # BT initialization
        logger().info(f'******BT initialization******')
        wifi_dut.interfaces.wifi.bt_start()

        for i in range(0, 3):
            # start BT inquiry with RSSI from DUT
            logger().info(f'******Start BT inquiry with RSSI from DUT******')
            wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
            time.sleep(duration / 1000)

            # Get Asynchronous messages
            events = wifi_dut.interfaces.wifi.get_async_events()
            assert len(events) > 0

            # Search for Inquiry type and Remote BT device address
            for event in events:
                event_data = event_data + str(event.event_data.decode())
                if bt_client_address in event_data and 'Inquiry_type = 1' in event_data:
                    logger().info(f'Remote BT address found ==> {bt_client_address}')
                    logger().info(f'Inquiry Type ==> {inq_type}')
                    break
            # Check for Class of Device in the inquiry results and extract RSSI value from it.
            if cod in event_data:
                test_data = event_data.split('COD = 203040')[1].strip(', RSSI :')
                test_data = test_data.split(',')[0].strip()
                logger().info(f'Remote device COD ==> {cod}')
                logger().info(f'RSSI ==> {test_data}')
                found = 1
                break
            else:
                logger().info(f'BT address {bt_client_address} not found')

        if found == 0:
            logger().info(f'BT address/Inquiry type/COD/RSSI are not found')
            assert False
        else:
            logger().info(f'BT address,Inquiry type,COD,RSSI are found in inquiry results')
            assert True
    logger().info(f"Test case executed in {t.duration} seconds")

def test_bt_extended_inquiry_C19982(wifi_dut, bt_client):  # T3561 in testrail
    inq_type = 2
    duration = 10000
    max_no_dev = 10
    found = 0
    cod = '203040'
    event_data = ''
    with TimeMeasurer() as t:
        # Configure Raspberry pi in slave mode
        bt_client_address = bt_client.interfaces.bluetooth.start_slave()
        assert bt_client_address is not None
        logger().info(f"Raspberry pi BD address {bt_client_address}")
        # Set COD to Raspberry Pi device
        logger().info(f"Set COD to Raspberry pi device")
        bt_client.interfaces.bluetooth.bt_adapter.set_class(cod)

        # BT initialization
        logger().info(f'******BT initialization******')
        wifi_dut.interfaces.wifi.bt_start()

        for i in range(0,3):
            # start BT inquiry with RSSI from DUT
            logger().info(f'******Start BT inquiry with RSSI from DUT******')
            wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
            time.sleep(duration / 1000)

            # Get Asynchronous messages
            events = wifi_dut.interfaces.wifi.get_async_events()
            assert len(events) > 0

            # Search for Inquiry type and Remote BT device address
            for event in events:
                event_data = event_data + str(event.event_data.decode())
                if bt_client_address in event_data and 'Inquiry_type = 2' in event_data:
                    logger().info(f'Remote BT address found ==> {bt_client_address}')
                    logger().info(f'Inquiry Type ==> {inq_type}')
                    break
            # Check for Class of Device in the inquiry results and extract RSSI value, remote device name and name length from it.
            if cod in event_data:
                test_data = event_data.split('COD = 203040')[1].strip(', RSSI :')
                rssi_val = test_data.split(',')[0].strip()
                logger().info(f'Remote device COD ==> {cod}')
                logger().info(f'RSSI ==> {rssi_val}')
                length = test_data.split('len:')[1].split(',')[0].strip()
                logger().info(f'Remote device name length ==> {length}')
                device_name = test_data.split('name:')[1].split(',')[0].split('\n')[0]
                logger().info(f'Remote device name ==> {device_name}')
                if int(length) != 0:
                    found = 1
                    break
            else:
                logger().info(f'BT address {bt_client_address} not found')

        if found == 0:
            logger().info(f'BT address/Inquiry type/COD/RSSI are not found')
            assert False
        else:
            logger().info(f'BT address, Inquiry type, COD, RSSI, remote device name and name length are found in inquiry results')
            assert True
    logger().info(f"Test case executed in {t.duration} seconds")

def test_bt_standard_inquiry_C19983(wifi_dut, bt_client):
    inq_type = 0
    duration = 10000
    max_no_dev = 10
    found = 0
    with TimeMeasurer() as t:
        # Configure Raspberry pi in slave mode
        logger().info(f'******Configure Raspberry pi in slave mode******')
        bt_client_address = bt_client.interfaces.bluetooth.start_slave()
        assert bt_client_address is not None
        logger().info(f"Raspberry pi BD address {bt_client_address}")

        # BT initialization
        logger().info(f'******BT initialization******')
        wifi_dut.interfaces.wifi.bt_start()

        # start BT standard inquiry from DUT
        logger().info(f'******Start BT standard inquiry from DUT******')
        wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
        time.sleep(duration / 1000)

        # Get Asynchronous messages
        events = wifi_dut.interfaces.wifi.get_async_events()
        assert len(events) > 0
        # Search for Inquiry type and Remote BT device address
        for i in range(0,3):
            for event in events:
                event_data = str(event.event_data.decode())
                if bt_client_address in event_data and 'Inquiry_type = 0' in event_data:
                    logger().info(f'Inquiry type is = {inq_type}')
                    logger().info(f'BT address found = {bt_client_address}')
                    found = 1
                    break
            if found == 1:
                logger().info(f'******BT address/ Inquiry type found = {bt_client_address}******')
                assert True
                break
            else:
                logger().info(f'******BT address/ Inquiry type not found = {bt_client_address}******')
                assert False
    logger().info(f"Test case executed in {t.duration} seconds")

def test_bt_inquiry_complete_C19984(wifi_dut, bt_client):
        inq_type = 1
        duration = 10000
        max_no_dev = 10
        event_found = 0
        with TimeMeasurer() as t:
            # Configure Raspberry pi in slave mode
            logger().info(f'******Configure Raspberry pi in slave mode******')
            bt_client_address = bt_client.interfaces.bluetooth.start_slave()
            assert bt_client_address is not None

            # BT initialization
            logger().info(f'******BT initialization******')
            wifi_dut.interfaces.wifi.bt_start()
            # start BT inquiry with RSSI from DUT
            logger().info(f'******Start BT inquiry with RSSI from DUT******')
            wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
            time.sleep(duration / 1000)

            # Get Asynchronous messages
            events = wifi_dut.interfaces.wifi.get_async_events()
            assert len(events) > 0

            # Search for Inquiry Complete Event
            for event in events:
                event_data = str(event.event_data.decode())
                if 'RSI_APP_EVENT_INQ_COMPLT' in event_data:
                    logger().info(f"inquiry complete event found")
                    event_found = 1
                    assert True
                    break
            if event_found == 0:
                assert False, logger().info(f"inquiry complete event not found")
        logger().info(f"Test case executed in {t.duration} seconds")

def test_bt_inq_complete_no_dev_C19985(wifi_dut, bt_client):
        inq_type = 1
        duration = 10000
        max_no_dev = 10
        event_found = 0
        #device_found = 0
        with TimeMeasurer() as t:
            # Configure Raspberry pi in slave mode
            logger().info(f'******Configure Raspberry pi in slave mode******')
            bt_client_address = bt_client.interfaces.bluetooth.start_slave()
            assert bt_client_address is not None
            #Disable scan
            logger().info(f'******Disable PIscan in Raspberry Pi ******')
            bt_client.interfaces.bluetooth.bt_adapter.set_noscan()

            # BT initialization
            logger().info(f'******BT initialization******')
            wifi_dut.interfaces.wifi.bt_start()
            # start BT inquiry with RSSI from DUT
            logger().info(f'******Start BT inquiry with RSSI from DUT******')
            wifi_dut.interfaces.wifi.bt_inquiry(inq_type, duration, max_no_dev)
            time.sleep(duration / 1000)

            # Get Asynchronous messages
            events = wifi_dut.interfaces.wifi.get_async_events()
            assert len(events) > 0

            # Search for Inquiry Complete Event
            event_data = ''
            for event in events:
                event_data = event_data + str(event.event_data.decode())
                if 'RSI_APP_EVENT_INQ_COMPLT' in event_data:
                    logger().info(f"inquiry complete event found")
                    break
            if bt_client_address not in event_data:
                event_found = 1
                assert True
            if event_found == 0:
                assert False, logger().info(f"inquiry complete event not found")
        logger().info(f"Test case executed in {t.duration} seconds")