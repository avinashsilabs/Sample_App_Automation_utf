import pytest
from utf.utils.time_measurer import TimeMeasurer
import time
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType, RS9116AsyncEvent
from queue import Empty as QueueEmpty

# Mark all tests in this module with 'framework_integration_test'
# and use fixtures parameterize_dut and parameterize_access_point
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("raspi_wifi"),
    pytest.mark.start_state("dut", device="reset", wifi="init"),
    pytest.mark.dut("rs9116_sapi")
]


@pytest.mark.test_src_map_id('SM11733')
def test_async_rejoin_errors(wifi_networked_dut, wifi_access_point, logger):
    # verify ping
    time.sleep(2)
    wifi_networked_dut.interfaces.wifi.ping(
        wifi_networked_dut.interfaces.wifi.ip.gateway
    )
    # stop ap
    logger.info("Disabling access point")
    wifi_access_point.interfaces.wifi.stop_ap()
    with TimeMeasurer() as t:
        logger.info("Waiting up to 180 seconds for rejoin error event...")
        sw = Stopwatch()
        while sw.elapsed_sec < 180:
            events = wifi_networked_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == RS9116AsyncEventType.RejoinError
            ]
            if len(rejoin_error_events):
                break
            time.sleep(0.1)
        else:
            assert False, "Did not receive an expected rejoin error event"
    logger.info(f"Received rejoin error event after {t.duration:.2f}s")


@pytest.mark.test_src_map_id('SM11737')
def test_async_rejoin_errors_using_queue(wifi_networked_dut, wifi_access_point, logger):
    # verify ping
    time.sleep(2)
    wifi_networked_dut.interfaces.wifi.ping(
        wifi_networked_dut.interfaces.wifi.ip.gateway
    )
    # stop ap
    logger.info("Disabling access point")
    wifi_access_point.interfaces.wifi.stop_ap()
    rejoin_error_queue = wifi_networked_dut.interfaces.wifi.event_queues[
        RS9116AsyncEventType.RejoinError
    ]
    with TimeMeasurer() as t:
        logger.info("Waiting up to 180 seconds for rejoin error event...")
        try:
            rejoin_error_queue.get(timeout=180)
        except QueueEmpty:
            assert False, "Did not receive an expected rejoin error event"
    logger.info(f"Received rejoin error event after {t.duration:.2f}s")


@pytest.mark.test_src_map_id('SM11742')
def test_async_rejoin_errors_using_wait_for_event(
    wifi_networked_dut, wifi_access_point, logger
):
    # verify ping
    time.sleep(2)
    wifi_networked_dut.interfaces.wifi.ping(
        wifi_networked_dut.interfaces.wifi.ip.gateway
    )
    # stop ap
    logger.info("Disabling access point")
    wifi_access_point.interfaces.wifi.stop_ap()
    with TimeMeasurer() as t:
        logger.info("Waiting up to 180 seconds for rejoin error event...")
        event = wifi_networked_dut.interfaces.wifi.wait_for_event(
            RS9116AsyncEventType.RejoinError, timeout=180
        )
        assert event is not None, "Did not receive an expected rejoin error event"
    logger.info(f"Received rejoin error event after {t.duration:.2f}s")
