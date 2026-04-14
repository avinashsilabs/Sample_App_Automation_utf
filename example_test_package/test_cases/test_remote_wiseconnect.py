import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


@pytest.mark.test_src_map_id('TC7373878293')
def test_remote_wiseconnect(remote_wiseconnect):
    with TimeMeasurer() as t:
        scan_results = remote_wiseconnect.interfaces.sapi.scan(ssid=None)
    logger().info(scan_results)
    assert len(scan_results) > 0
    logger().info(f"Scan in {t.duration} seconds")