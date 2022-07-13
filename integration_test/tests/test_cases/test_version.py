import pytest
from utf_wiseconnect.utils.rs911x_version import parse_version

# Mark all tests in this module with 'framework_integration_test'
# and use fixtures parameterize_dut and parameterize_access_point
pytestmark = [
    pytest.mark.framework_integration_test,
]


def test_version(wifi_dut, logger):
    expected_version = parse_version()
    if expected_version is None:
        pytest.skip("No firmware version for 9116x in manifest, skipping test_version")

    logger.info(f"Expected FW version: {expected_version}")
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"Actual version: {result}")
    assert result == expected_version
