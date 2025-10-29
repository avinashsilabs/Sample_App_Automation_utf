from utf.utils.logger import get_logger
import time

def logger():
    return get_logger(__name__)


def test_service_discovery(service_discovery):
    status = service_discovery.interfaces.sd.get_status()
    logger().info(f"Status {status}")
    time.sleep(5)
    service_discovery.interfaces.sd.start_discovering_services()
    for _ in range(120):
        logger().info("Do Some Thing")
        time.sleep(1)
    service_discovery.interfaces.sd.stop_discovering_services()
    time.sleep(10)

