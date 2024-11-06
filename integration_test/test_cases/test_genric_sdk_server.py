from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


def test_sdk_server(sdk_server):
    sdk_server.interfaces.server.start_server()
    for _ in range(120):
        logger().info("Do Some Thing")
    sdk_server.interfaces.server.stop_server()
