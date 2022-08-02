import pytest
from utf.interfaces.wifi import (
    Standard,
    Channel,
    Cipher,
    SecurityMode,
)
from .common import run_ap_configuration_test

# Mark all tests in this module with 'framework_integration_test' and specify wifi ap & client
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("dlink810_ap"),
    pytest.mark.wifi_client("raspi_wifi"),
]


@pytest.fixture(scope="class")
def class_teardown(request):
    yield
    request.cls.cleanup()


@pytest.mark.usefixtures("class_teardown")
class TestAccessPointConfig:
    wifi_access_point_to_clean_up = None

    def set_access_point_for_cleanup(self, wifi_access_point_to_clean_up):
        self.__class__.wifi_access_point_to_clean_up = wifi_access_point_to_clean_up

    @classmethod
    def cleanup(cls):
        cls.wifi_access_point_to_clean_up.interfaces.wifi.stop_ap()

    @pytest.mark.skip
    @pytest.mark.start_state("wifi_access_point", wifi="default")
    @pytest.mark.end_state("wifi_access_point", wifi="ap_enabled")
    @pytest.mark.parametrize(
        "security, standard, channel, cipher",
        [
            (SecurityMode.WPA2, Standard.n, 1, Cipher.TKIP_AES),
            (SecurityMode.WPA2, Standard.g | Standard.n | Standard.b, 6, Cipher.AES),
            (
                SecurityMode.WPA2,
                Standard.g,
                Channel.Automatic2p4G,
                Cipher.AES,
            ),
        ],
    )
    def test_wifi_ap_configuration_lb(
        self,
        wifi_client,
        wifi_access_point,
        security,
        standard,
        channel,
        cipher,
        logger,
    ):
        logger.info("Running tests on DLink 810 for 2.4GHz Band")
        self.set_access_point_for_cleanup(wifi_access_point)
        try:
            run_ap_configuration_test(
                wifi_client, wifi_access_point, security, standard, channel, cipher
            )
        except AssertionError as e:
            logger.error(str(e))
            raise

    @pytest.mark.skip
    @pytest.mark.start_state("wifi_access_point", wifi="default")
    @pytest.mark.end_state("wifi_access_point", wifi="ap_enabled")
    @pytest.mark.parametrize(
        "security, standard, channel, cipher",
        [
            (SecurityMode.WPA2, Standard.n, 36, Cipher.TKIP_AES),
            (SecurityMode.WPA2, Standard.ac | Standard.n, 153, Cipher.AES),
            (
                SecurityMode.WPA2,
                Standard.ac | Standard.a | Standard.n,
                Channel.Automatic5G,
                Cipher.AES,
            ),
        ],
    )
    def test_wifi_ap_configuration_hb(
        self,
        wifi_client,
        wifi_access_point,
        security,
        standard,
        channel,
        cipher,
        logger,
    ):
        logger.info("Running tests on DLink 810 for 5GHz Band")
        self.set_access_point_for_cleanup(wifi_access_point)
        try:
            run_ap_configuration_test(
                wifi_client, wifi_access_point, security, standard, channel, cipher
            )
        except AssertionError as e:
            logger.error(str(e))
            raise
