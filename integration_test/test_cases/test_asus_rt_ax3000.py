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
    pytest.mark.wifi_access_point("asus_rt_ax3000_ap"),
    pytest.mark.wifi_client("raspi_wifi"),
]


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
                Standard.g | Standard.n | Standard.b | Standard.ax,
                Channel.Automatic2p4G,
                Cipher.AES,
            ),
        ],
    )
    @pytest.mark.test_src_map_id('SM11722')
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
        logger.info("Running tests on ASUS RT AX300 for 2.4GHz Band")
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
            (SecurityMode.WPA2, Standard.n | Standard.ac, 36, Cipher.AES),
            (SecurityMode.WPA2, Standard.a | Standard.n | Standard.ac, 153, Cipher.AES),
            (
                SecurityMode.WPA2,
                Standard.a | Standard.n | Standard.ac | Standard.ax,
                Channel.Automatic5G,
                Cipher.AES,
            ),
        ],
    )
    @pytest.mark.test_src_map_id('SM11728')
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
        logger.info("Running tests on ASUS RT AX300 for 5GHz Band")
        self.set_access_point_for_cleanup(wifi_access_point)
        try:
            run_ap_configuration_test(
                wifi_client, wifi_access_point, security, standard, channel, cipher
            )
        except AssertionError as e:
            logger.error(str(e))
            raise
