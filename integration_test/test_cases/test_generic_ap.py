import pytest
from utf.interfaces.wifi import (
    Standard,
    Channel,
    Cipher,
    SecurityMode,
)
from .common import run_ap_configuration_test


@pytest.fixture(scope="class")
def class_teardown(request):
    yield
    request.cls.cleanup()


@pytest.mark.usefixtures("class_teardown")
class TestAccessPointConfig:
    wifi_access_point_to_clean_up = None

    @classmethod
    def set_access_point_for_cleanup(cls, wifi_access_point_to_clean_up):
        cls.wifi_access_point_to_clean_up = wifi_access_point_to_clean_up

    @classmethod
    def cleanup(cls):
        cls.wifi_access_point_to_clean_up.interfaces.wifi.stop_ap()

    @pytest.mark.start_state("wifi_access_point", wifi=None)
    @pytest.mark.end_state("wifi_access_point", wifi=None)
    @pytest.mark.wifi_access_point("asus_rt_ax3000_ap")
    @pytest.mark.wifi_client("raspi_wifi")
    @pytest.mark.parametrize("security, standard, channel, cipher", [('WPA2', 'n', 6, 'TKIP_AES')])
    def test_wifi_ap_configuration(
        self,
        wifi_client,
        wifi_access_point,
        security,
        standard,
        channel,
        cipher,
        logger,
    ):
        logger.info(f"Running tests on {wifi_access_point.name} for channel {channel}")
        self.set_access_point_for_cleanup(wifi_access_point)
        try:
            run_ap_configuration_test(
                wifi_client, wifi_access_point, security, standard, channel, cipher
            )
        except AssertionError as e:
            logger.error(str(e))
            raise


