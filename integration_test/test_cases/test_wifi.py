import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.wifi import WlanError

# Mark all tests in this module with 'framework_integration_test'
# and use fixtures parameterize_dut and parameterize_access_point
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("raspi_wifi"),
    pytest.mark.dut("rs9116_sapi")
]

# TODO: 'associated' device state doesn't work because it does not use the correct access point
#@pytest.mark.start_state("wifi_dut", wifi="associated")
#def test_wifi_dhcp(wifi_dut, logger):
#    with TimeMeasurer() as t:
#        result = wifi_dut.interfaces.wifi.start_ip()
#    assert isinstance(
#        result, wifi_dut.interfaces.wifi.IPConfig
#    ), f"Failed to get IP address. Result = {result}"
#    logger.info(f"Got {result} via DHCP in {t.duration} seconds")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_access_point", wifi=None)
@pytest.mark.wifi_access_point("dlink810_ap")
def test_prepare_static_ap(wifi_access_point, logger):
    logger.info(f"Starting tests on {wifi_access_point.name}")


def test_wifi_dhcp(wifi_associated_dut, logger):
    with TimeMeasurer() as t:
        result = wifi_associated_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_associated_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    logger.info(f"Got {result} via DHCP in {t.duration} seconds")


def test_wifi_ping(wifi_networked_dut, logger):
    with TimeMeasurer() as t:
        wifi_networked_dut.interfaces.wifi.ping(wifi_networked_dut.interfaces.wifi.ip.gateway)
    logger.info(f"Ping completed in {t.duration} seconds")


def test_wifi_leave(wifi_networked_dut, logger):
    with TimeMeasurer() as t:
        wifi_networked_dut.interfaces.wifi.leave()
    logger.info(f"Leave completed in {t.duration} seconds")
    with pytest.raises(WlanError) as exception_info:
        wifi_networked_dut.interfaces.wifi.leave(skip_check_for_association=True)
    assert exception_info.value.error_code == WlanError.COMMAND_GIVEN_IN_INCORRECT_STATE
