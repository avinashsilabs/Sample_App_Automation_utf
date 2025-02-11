from utf.utils.logger import get_logger
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xCoexMode
)
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.thread_base import ThreadBase
import ipaddress
import random
import string


def logger():
    return get_logger(__name__)


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, http_client=None, wifi_client=None,
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
        self.wifi_client = wifi_client
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

                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()

                return

            if self.test_name == '476928':
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

                    self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                    self.wifi_dut.interfaces.http.http_put(self.http_server.interfaces.http, self.index_path,
                                                           server_port=443)

                    self.wifi_dut.interfaces.wifi.http_client_deinit()

                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()

                return

            if self.test_name == '537908':
                logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, ip_version='ipv6',
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         channel=self.wifi_access_point.interfaces.wifi.channel)
                for i in range(5):
                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

                    self.wifi_dut.interfaces.wifi.http_client_init(https_enable=False, ip_version='ipv6')
                    remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)

                    self.wifi_dut.interfaces.http.http_put(server=None, resource_path=self.index_path,
                                                           server_ip=f'"{remote_ip}"', server_port=80)

                    self.wifi_dut.interfaces.wifi.http_client_deinit()

                    power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                        filter_name="power_mgmt_bit")
                    assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                               'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()

                return
                
            if self.test_name == '37576':
                logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

                for _ in range(5):
                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel)

                    self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
                    self.wifi_dut.interfaces.wifi.http_client_init(https_enable=True)

                    self.wifi_dut.interfaces.http.http_put(self.http_server.interfaces.http, self.index_path,
                                                           server_port=443)

                    self.wifi_dut.interfaces.wifi.http_client_deinit()

                    self.wifi_dut.interfaces.wifi.leave()

                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()

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

    @classmethod
    def random_ipv6_addr(cls, network):
        """
        Generate a random IPv6 address in the given network
        Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
        Returns an IPv6Address object.
        """
        net = ipaddress.IPv6Network(network)
        # Which of the network.num_addresses we want to select?
        addr_no = random.randint(0, net.num_addresses)
        # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
        network_int = int.from_bytes(net.network_address.packed, byteorder="big")
        addr_int = network_int + addr_no
        addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
        return addr


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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_put_functionality_c19231(http_server, wifi_dut, sniffer_filter,
                                                wifi_sniffer, wifi_access_point, index_path,
                                                sl_collections, http_client):
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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_get_after_put_functionality_c19232(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                          wifi_access_point, index_path, sl_collections, http_client):
    """verify whether DUT is sending error (0x0015) to host when we issue http get command after http put create
    success"""
    try:
        test_name = '19231'

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, http_server=http_server,
                              test_name=test_name, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                              wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.http.http_client_request_init(http_server.interfaces.http, index_path)
        wifi_dut.interfaces.http.http_client_send_request(http_method_type=3)
        wifi_dut.interfaces.http.http_client_request_init(http_server.interfaces.http, index_path, http_method_type=0)
        wifi_dut.interfaces.http.http_client_send_request(http_method_type=0, expected_status=SLStatus.SL_STATUS_SI91X_MEMORY_FAILED_FROM_MODULE)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        power_save_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=wlan_obj.ap_mac_address,
            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_post_after_put_functionality_c19233(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                           wifi_access_point, index_path, sl_collections, http_client):
    """verify whether DUT is sending error (0x10015) to host when we issue http post command after http put create
    success"""
    try:
        test_name = '19231'

        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, http_server=http_server,
                              test_name=test_name, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                              wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.http.http_client_request_init(http_server.interfaces.http, index_path)
        wifi_dut.interfaces.http.http_client_send_request(http_method_type=3)
        wifi_dut.interfaces.http.http_client_request_init(http_server.interfaces.http, index_path, http_method_type=1)
        wifi_dut.interfaces.http.http_client_send_request(http_method_type=1, expected_status=SLStatus.SL_STATUS_SI91X_MEMORY_FAILED_FROM_MODULE)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        power_save_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=wlan_obj.ap_mac_address,
            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_put_functionality_with_exact_buffer_c19234(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                                  wifi_access_point, index_path, sl_collections,
                                                                  http_client):
    """	http put packet functionality with exact data buffer with the given buffer size"""
    try:
        test_name = '19231'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, http_server=http_server,
                              test_name=test_name, sl_collections=sl_collections, sniffer_filter=sniffer_filter,
                              wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)

        wifi_dut.interfaces.wifi.http_client_deinit()

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        power_save_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=wlan_obj.ap_mac_address,
            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                   'packet_count'] > 0, "Unable to find NULL-Data frame packets with power save bit = 1"

        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)
        assert status_client, "failed to load the https data"

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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_put_without_wlan_disconnect_c37541(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                          wifi_access_point, index_path, http_client,
                                                          sl_collections):
    """Verify whether if HTTP PUT without WLAN disconnect"""
    try:
        test_name = '37541'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, index_path=index_path,
                              http_server=http_server, test_name=test_name, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_http_put_without_extended_header_c37573(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                          wifi_access_point, index_path, http_client,
                                                          sl_collections):
    """HTTP PUT Functionality when the extended Header is not provided"""
    try:
        test_name = '19231'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, index_path=index_path,
                              http_server=http_server, test_name=test_name, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)
        wifi_dut.interfaces.wifi.http_client_deinit()

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        power_save_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], da_addr=wlan_obj.ap_mac_address,
            filter_name="power_mgmt_bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=power_save_filter)[
                   'packet_count'], "Unable to find NULL-Data frame packets with power save bit = 1"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "wan_ipv6_address": WLanThread().random_ipv6_addr("2401:4900:1cb3::/48"),
                               "security": "Open"}
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
    }
)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_http_put_with_ipv6_stateful_c537908(firmware_loader, http_server, wifi_dut, http_client,
                                                      wifi_access_point, wifi_sniffer, sl_collections, sniffer_filter,
                                                      wifi_client):
    try:
        test_name = '537908'
        index_path = "index.html"
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, wifi_client=wifi_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path,
                              sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_https_put_functionality_c37576(http_server, wifi_dut, http_client, wifi_access_point, wifi_sniffer,
                                                 sl_collections, sniffer_filter, wifi_client, index_path):
    """HTTPs PUT Functionality when the extended Header is not provided"""
    try:
        test_name = '37576'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                              http_client=http_client, wifi_client=wifi_client,
                              test_name=test_name, sl_collections=sl_collections, http_server=http_server,
                              index_path=index_path, sniffer_filter=sniffer_filter)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.DNSClient,
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"cgi-bin/cgi_example.py"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_https_put_without_wlan_disconnect_c476928(http_server, wifi_dut, sniffer_filter, wifi_sniffer,
                                                            wifi_access_point, index_path, http_client,
                                                            sl_collections):
    """Verify HTTPS PUT functionality in loop without WLAN Disconnect"""
    try:
        test_name = '476928'
        wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, index_path=index_path,
                              http_server=http_server, test_name=test_name, sl_collections=sl_collections,
                              sniffer_filter=sniffer_filter, wifi_sniffer=wifi_sniffer)
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
