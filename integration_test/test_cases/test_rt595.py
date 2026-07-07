import time
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band, RS9116CoexMode, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116PowerSaveModes
from utf_wiseconnect.utils.rs911x_version import parse_version, extract_version
from utf.utils.time_measurer import TimeMeasurer
import pytest
from utf.utils.logger import get_logger
from utf import UtfDatabaseProperties
import time

def logger():
    return get_logger(__name__)

@pytest.fixture(autouse=True)
def reset_dut():
    # override the reset_dut fixture to do nothing
    pass

@pytest.mark.test_src_map_id('TC7249691589')
def test_scan(wifi_dut):
    time.sleep(6)
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")

@pytest.mark.ble_client("nrf_53840_cli")
@pytest.mark.test_src_map_id('TC7786430594')
def test_nrf5340(ble_client):
    time.sleep(6)
    ble_client.interfaces.wifi.ble_init()
    time.sleep(6)
    ble_client.interfaces.wifi.register_callbacks()
    time.sleep(6)
    ble_client.interfaces.wifi.start_adv()
   

@pytest.mark.ble_sniffer("rf_creations_sniffer")
def test_rf_creations_sniffer(ble_sniffer):
        logger().info("Connecting to BLE sniffer...")
        ble_sniffer.interfaces.sniffer.connect()
        time.sleep(5)  # Capture for 5 seconds
        logger().info("Starting BLE sniffer capture...")
        ble_sniffer.interfaces.sniffer.start_capture()
        time.sleep(15)  # Capture for 15 seconds
        logger().info("Stopping BLE sniffer capture...")
        ble_sniffer.interfaces.sniffer.stop_capture()
        # disconnection is handled in teardown as it is invoking as part of close, so no need to call disconnect here

