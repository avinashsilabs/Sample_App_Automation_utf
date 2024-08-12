from utf.utils.logger import get_logger
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xCustomFeatureBitMap
)
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, http_client=None,
                 test_name=None, sl_collections=None, http_server=None, index_path=None, sniffer_filter=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.http_server = http_server
        self.test_name = test_name
        self.index_path = index_path
        self.http_client = http_client
        self.sniffer_filter = sniffer_filter
        self.power_save_filter = None
        self.dut_addr = None
        self.ap_mac_address = None

    def run(self):
        try:
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            if self.test_name == '37541':
                logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         channel=self.wifi_access_point.interfaces.wifi.channel)
                for i in range(5):
                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

                    self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)

                    self.wifi_dut.interfaces.http.http_put(self.http_server.interfaces.http, self.index_path)

                    self.wifi_dut.interfaces.wifi.http_client_deinit()

                    logger().info("Stopping sniffer capture")
                    self.wifi_sniffer.interfaces.capture.stop_capture()

                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                return

            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     channel=self.wifi_access_point.interfaces.wifi.channel)

            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": 0,
        "features": Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
    }
)
@pytest.mark.http_server("python_http_server")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_put_functionality_c19231(http_server, wifi_dut, sniffer_filter,
                                                wifi_sniffer, wifi_access_point, index_path,
                                                sl_collections):
    """HTTP PUT create functionality by enabling http feature in oper-mode"""
    try:
        test_name = '19231'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, http_server=http_server,
                              test_name=test_name, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                              wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)
        power_save_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=wlan_obj.ap_mac_address,
            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"
        wifi_dut.interfaces.wifi.http_client_deinit()

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": 0,
        "features": Si91xFeatureBitMap.OpenMode,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
    }
)
@pytest.mark.http_server("python_http_server")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_put_without_wlan_disconnect_c37541(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                          wifi_access_point, index_path,
                                                          sl_collections):
    """Verify whether if HTTP PUT without WLAN disconnect"""
    test_name = '37541'
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, index_path=index_path,
                          http_server=http_server, test_name=test_name, sl_collections=sl_collections,
                          sniffer_filter=sniffer_filter, wifi_sniffer=wifi_sniffer)
    wlan_obj.start()
    wlan_obj.wait_for_exit()
