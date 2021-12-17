import pytest
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BTSocketRole
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
import time
from devices.rs911x import RS9116AsyncEventType

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

def test_bt_standard_inquiry(wifi_dut, bt_client):    #T3563 in testrail
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
        for event in events:
            event_data = str(event.event_data.decode())
            logger().info(f'event_data ==== {event_data}')
            if bt_client_address in event_data and 'Inquiry_type = 0' in event_data:
                    logger().info(f'Inquiry type is = {inq_type}')
                    logger().info(f'BT address found = {bt_client_address}')
                    found = 1
                    assert True
                    break

        if found == 1:
            logger().info(f'******BT address/ Inquiry type found = {bt_client_address}******')
            assert True
        else:
            logger().info(f'******BT address/ Inquiry type not found = {bt_client_address}******')
            assert False
    logger().info(f"Test case executed in {t.duration} seconds")

def test_bt_inquiry_complete(wifi_dut, bt_client):  # T3564 in testrail
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

def test_bt_inq_complete_no_dev(wifi_dut, bt_client):  # T3565 in testrail
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






