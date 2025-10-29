from utf.utils.logger import get_logger
import time

def logger():
    return get_logger(__name__)


def test_service_advertisement(service_advertisement):
    status = service_advertisement.interfaces.sa.get_status()
    logger().info(f"Status {status}")
    time.sleep(5)
    service_advertisement.interfaces.sa.start_advertising_services()
    for _ in range(120):
        logger().info("Do Some Thing")
        time.sleep(1)
    service_advertisement.interfaces.sa.stop_advertising_services()
    time.sleep(10)

