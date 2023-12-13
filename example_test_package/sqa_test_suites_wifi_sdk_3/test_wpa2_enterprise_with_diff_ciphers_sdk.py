import time
import pytest
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap,
                                                   Si91xOperatingMode,
                                                   Si91xCustomFeatureBitMap,
                                                   Si91xConfigFeatureBitMap,
                                                   Si91xTCPIPFeatureBitMap,
                                                   Si91xExtCustomFeatureBitMap,
                                                   Si91xExtTCPIPFeatureBitMap,
                                                   Si91xCertificateType, Si91xCertIdentifier,
                                                   Si91xPowerSaveProcedureTypes, Si91xJoinFeatureBitMap
                                                   )
from utf.utils.logger import get_logger
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf.utils.stopwatch import Stopwatch


def logger():
    return get_logger(__name__)


"""
    This test plan aims to connect the wifi ap in enterprise mode
        1. Configuration of DUT in 2G mode
        2. Verifying eap connection in tls mode
        3. Verifying eap connection in ttls mode
        4. Verifying eap connection in peapv0 mode
        5. Verifying eap connection by loading wrong certificate in tls mode
        6. Verifying eap connection by loading no ceritificate in tls mode
        7. Verifying eap connection by setting expired date in tls mode

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's) -ASUS
        4. Sniffer -NUC
        5. Free Radius Server (For now running on NUC)

    Author: Benazeer K

"""


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None, test_case_no=None,
                 ap_mac_address=None, conn_status=True, eap_type="tls", sniffer_filter=None, sl_collections=None):

        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.sl_collections = sl_collections
        self.test_case_no = test_case_no

    def verify_sniffer_validation(self):
        device_address = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address, 'ta_addr': self.dut_mac_address}
        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'power_mgmt_bit', 3: 'null_data_powersave',
                        4: 'eap_type_tls_verification'}

        output = self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                   device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

        device_address_1 = {'sa_addr': self.ap_mac_address, 'da_addr': self.dut_mac_address }
        if self.wifi_access_point.interfaces.wifi.security == SecurityMode.WPAEnterprise:
            filters_name_1 = {1: 'beacon_wpa2_entr_wfa_check'}

        else:
            filters_name_1 = {1: 'beacon_wpa2_entr_akms_check'}
        output_1 = self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                   device_address_1, filters_name=filters_name_1)
        logger().info(f'\n OUTPUT 2 = {output_1}\n')
        assert all(output.values()), 'Unable to find expected filter'

        if self.test_case_no != 113845 and self.test_case_no != 113846:

            device_address_2 = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address}
            if self.test_case_no == 113821:
                filters_name_12 = {1: 'eap_tls_handshake_aes256_sha256'}
            if self.test_case_no == 113822:
                filters_name_12 = {1: 'eap_tls_handshake_aes128_sha128'}
            if self.test_case_no == 113823:
                filters_name_12 = {1: 'eap_tls_dhe_rsa_aes256'}
            if self.test_case_no == 113824:
                filters_name_12 = {1: 'eap_tls_dhe_rsa_aes128'}
            if self.test_case_no == 113825:
                filters_name_12 = {1: 'eap_tls_aes256_sha256'}
            if self.test_case_no == 113826:
                filters_name_12 = {1: 'eap_tls_aes128_sha256'}
            if self.test_case_no == 113827:
                filters_name_12 = {1: 'eap_tls_aes256_sha'}
            if self.test_case_no == 113832:
                filters_name_12 = {1: 'aes256_sha256_and_aes256_sha'}
            if self.test_case_no == 113833:
                filters_name_12 = {1: 'eap_tls_all_cipher'}
            if self.test_case_no == 113828:
                filters_name_12 = {1: 'eap_tls_aes128_sha'}
            if self.test_case_no == 113835:
                filters_name_12 = {1: 'eap_tls_handshake_aes256_sha256_v1'}
            if self.test_case_no == 113836:
                filters_name_12 = {1: 'eap_tls_handshake_aes128_sha128_v1'}
            if self.test_case_no == 113837:
                filters_name_12 = {1: 'eap_tls_aes256_sha_v1'}
            if self.test_case_no == 113838:
                filters_name_12 = {1: 'eap_tls_aes128_sha_v1'}
            if self.test_case_no == 113843:
                filters_name_12 = {1: 'eap_tls_all_cipher_v1'}
            if self.test_case_no == 113842:
                filters_name_12 = {1: 'eap_tls__aes256_sha256_aes256_sha_v1_0'}

            output_2 = self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                                                 device_address_2,
                                                                                 filters_name=filters_name_12)
            logger().info(f'\n OUTPUT 2 = {output_2}\n')
            assert all(output.values()), 'Unable to find expected filter'

    def verify_sniffer_validation_peap(self):
        device_address = {'sa_addr': self.dut_mac_address, 'da_addr': self.ap_mac_address,
                          'ta_addr': self.dut_mac_address}
        filters_name = {1: 'assoc_req_resp_eapol_4_way_handshake', 2: 'power_mgmt_bit', 3: 'eap_type_peap_verification',
                        4: 'eap_type_peap_verification'}

        output = self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                                           device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'

        device_address_1 = {'sa_addr': self.ap_mac_address, 'da_addr': self.dut_mac_address }

        filters_name_1 = {1: 'beacon_wpa2_entr_akms_check'}
        output_1 = self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                   device_address_1, filters_name=filters_name_1)
        logger().info(f'\n OUTPUT 2 = {output_1}\n')
        assert all(output.values()), 'Unable to find expected filter'

    def verify_sniffer_for_negative_scenarios(self):
        device_address = {'da_addr': self.dut_mac_address, 'sa_addr': self.ap_mac_address,
                          'ta_addr': self.dut_mac_address}
        filters_name = {1: 'beacon_wpa2_entr_akms_check', 2: 'eap_connection_failure'}

        output = self.sl_collections.sniffer_validation_for_packet_filters(self.wifi_sniffer, self.sniffer_filter,
                                                                           device_address, filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output}\n')
        assert all(output.values()), 'Unable to find expected filter'


class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None, eap_type=None, net_perf_client=None, protocol=None,
                 eap_type_tls_no_cert=True, test_case_no=None, set_rtc=True, data_transfer=True, traffic_type=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.test_name = test_name
        self.eap_type = eap_type
        self.data_transfer = data_transfer
        self.eap_type_tls_no_cert = eap_type_tls_no_cert
        self.dut_addr = None
        self.device_ip = None
        self.test_case_no = test_case_no
        self.set_rtc = set_rtc
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.traffic_type = traffic_type

    def run(self):
        try:
            if self.test_case_no == 113821:
                transfer_type = 1
                protocol = 6
                throughput_type = 1
                size = 1460
            if self.eap_type == "tls" or self.eap_type == "peap" or self.eap_type == "ttls":
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.eap_type,
                                                                        ping_after_power_save=False,
                                                                        channel=self.wifi_access_point.interfaces.wifi.channel, retry_count=3
                                                                        )
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                time.sleep(2)
                if self.data_transfer:
                    host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                    logger().info(f"Remote device ip :{host_ip}")
                    if self.traffic_type == "TX":
                        # starting iperf
                        timeout = 40
                        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol)
                        self.net_perf_client.interfaces.net_perf.start()
                        logger().info("sending data from DUT")
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            timeout=timeout+2)
                        # # get and print throughput
                        time.sleep(5)
                        tp = self.net_perf_client.interfaces.net_perf.process_output()
                        assert tp is not None, "Throughput not found"
                        logger().info("data transfer successful")
                        time.sleep(3)
                    if self.traffic_type == "RX":
                        # Iperf Client Started
                        if self.protocol == "UDP":
                            bandwidth = "68M"
                            self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                            self.dut_addr['device_ip'], protocol=self.protocol, bandwidth=bandwidth)
                        else:
                            self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                            self.dut_addr['device_ip'], protocol=self.protocol)

                        self.net_perf_client.interfaces.net_perf.start()

                        logger().info("receiving data from Host")
                        # open socket and listen for data
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0)
                        logger().info("data received is successful")
                        time.sleep(3)

                self.wifi_dut.interfaces.wifi.leave()

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES256_SHA256_TLSv12_C113821(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                            protocol, net_perf_client, wifi_client, radius_server,
                                                            sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=4)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113821)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES128_SHA256_TLSv12_C113822(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                            protocol, net_perf_client, wifi_client, radius_server,
                                                            sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=8 | 1)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113822)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv12_C113823(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         protocol, net_perf_client, wifi_client, radius_server,
                                                         sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=16)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113823)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv12_C113824(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         protocol, net_perf_client, wifi_client, radius_server,
                                                         sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=32)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113824)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_AES256_SHA256_TLSv12_C113825(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                    protocol, net_perf_client, wifi_client, radius_server,
                                                    sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=64)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113825)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_AES128_SHA256_TLSv12_C113826(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                    protocol, net_perf_client, wifi_client, radius_server,
                                                    sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=128)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113826)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_AES256_SHA_TLSv12_C113827(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=256)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113827)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_RSA_AES256_SHA256_and_RSA_AES256_SHA_TLSv12_C113832(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=20)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113832)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_all_ciphers_TLSv12_C113833(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=8188)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113833)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_AES128_SHA_TLSv12_C113828(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=512)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113828)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES256_SHA_TLSv10_C113835(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=16)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113835)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES128_SHA_TLSv10_C113836(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=32)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113836)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_AES256_SHA_TLSv10_C113837(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=256)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address,test_case_no=113837)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_AES128_SHA_TLSv10_C113838(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=512)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113838)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_all_ciphers_TLSv10_C113843(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 protocol, net_perf_client, wifi_client, radius_server, sl_collections,
                                                 request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=8188)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113843)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_EAP_DHE_RSA_AES128_SHA256_ca_cert_1_C113845(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                            protocol, net_perf_client, wifi_client, radius_server,
                                                            sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=8 | 1)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113822)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_DHE_RSA_AES128_SHA256_DHE_RSA_AES128_SHA_TLSv10_C113842(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                            protocol, net_perf_client, wifi_client, radius_server,
                                                            sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=4 | 16)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113842)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose |
                              Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_SSL_16K_RECORDBIT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp |
                           Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_conn_with_16k_record_size_C113846(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                            protocol, net_perf_client, wifi_client, radius_server,
                                                            sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap dhe-rsa tls method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
                                                                 # eap_flags=4 | 16)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="tls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=113846)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_sdk_WPA2_EAP_PEAP_ca_cert_flag_set_1_C113854(
        wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server, protocol, net_perf_client,
        wifi_client,
        sl_collections, request, utf_constants):
    """ WPA2 Enterprise connection in EAP PEAP Method with ca_cert_required flag set to 1 """

    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=2)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="peap", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packet in sniffer'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=dut_mac_address,
                                                                                        filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_sdk_WPA2_EAP_PEAP_ca_cert_flag_set_1_cert_not_loaded_C113855(
        wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server, sl_collections, request):
    """ WPA2 Enterprise conn. in EAP PEAP Method with ca_cert_required flag set to 1 and certificate is not loaded """

    try:
        test_name = request.node.name
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=2)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa2_enterprise", uid="user1", enc="peap", timeout_ms=1,
                                      expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info(f"Connection failed when certificate is not loaded into the device, "
                      f"error code 0x10008 which is expected")
        wifi_dut.interfaces.wifi.start_ip(expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
        logger().info(f"IP config failed when command given in incorrect state, error code 0x10021 which is expected")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packet in sniffer'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        da_addr=dut_mac_address,
                                                                                        filter_name='eap_connection_failure')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP failure frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_sdk_WPA2_EAP_TTLS_ca_cert_flag_set_1_C113856(
        wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server, protocol, net_perf_client,
        wifi_client, sl_collections, request, utf_constants):

    """ WPA2 Enterprise connection in EAP TTLS Method with ca_cert_required flag set to 1 """

    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=2)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="ttls", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packet in sniffer'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=dut_mac_address,
                                                                                        filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip('Skip the test case as we dont have the support to run on hostapd server')
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_sdk_WPA2_EAP_ttls_ca_cert_flag_set_1_cert_not_loaded_C113857(
        wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server, sl_collections, request):

    """ WPA2 Enterprise conn. in EAP TTLS Method with ca_cert_required flag set to 1 and certificate is not loaded """

    try:
        test_name = request.node.name
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=2)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa2_enterprise", uid="user1", enc="ttls", timeout_ms=1,
                                      expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
        logger().info(
            f" Connection failed when expired certificate is loaded into the device,observed error code "
            f"  0x10008 which is expected")
        wifi_dut.interfaces.wifi.start_ip(expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
        logger().info(f"IP config failed when command given in incorrect state, error code 0x10021 which is expected")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f'dut_mac_address is {dut_mac_address}')
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find packet in sniffer'

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                        da_addr=dut_mac_address,
                                                                                        filter_name='eap_connection_failure')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP failure frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wsdk_WPA2_eap_conn_with_peap_cert_loaded_C113858(
        wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server, protocol, net_perf_client,
        wifi_client,
        sl_collections, request, utf_constants):
    """ WPA2 Enterprise connection in EAP PEAP Method when the ca_cert_required flag is set to 0 and the
    certificate is loaded """

    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0,
                                                                 eap_flags=1)
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     protocol=protocol, net_perf_client=net_perf_client, test_name=test_name,
                                     eap_type="peap", sl_collections=sl_collections, data_transfer=True,
                                     test_case_no=113821, traffic_type="TX")
        for i in range(0, iter_count):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            time.sleep(3)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(1)
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                        ap_mac_address=ap_mac_address, test_case_no=None)
        sniffer_verification.verify_sniffer_validation_peap()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user-footer.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_EAP_footer_removed_TLSv12_C113863(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity footer removed in certs"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '53', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)



@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user-header.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_EAP_header_removed_TLSv12_C113862(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity header removed in certs"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '53', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_EAP_non_supported_ciphers_TLSv12_C113834(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity non supported chipers method"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0,
                                                                     eap_flags=1024)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '47', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_EAP_non_supported_ciphers_TLSv10_C113844(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity with non supported ciphers in TLS 1.0"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0,
                                                                     eap_flags=1024)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '47', "Unable to get expected reason code hence test is failed"
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_with_wrong_pwd_TLSv10_C113884(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, sl_collections, request, utf_constants):
    """ This test case Verifies with wrong password with wpa2 security"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase='123456789',
                                          security='wpa2',
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_mac_address,
                                                                                            filter_name='deauthentication')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], 'Unable to find packet in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wsdk_WPA2_Eap_Conn_with_invalid_date_C113891(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                       cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)
            wifi_dut.interfaces.wifi.load_certs(
                eap_cert=["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            time.sleep(2)
            wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1950)
            time.sleep(2)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '4B', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_EAP_Conn_TLS_when_no_cert_C113852(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                       cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '2B', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["server-cert.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
def test_wsdk_WPA2_EAP_TLS_conn_with_wrong_cert_C113850(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                 wifi_client, radius_server, sl_collections, request, utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity with wrong certs"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)
            logger().info(f"Loading Certs")
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa2_enterprise", uid="user1", enc="tls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            events = wifi_dut.interfaces.wifi.get_async_events()
            rejoin_error_events = [
                event
                for event in events
                if event.event_type == AsyncEventIdentifiers.WIFICONNECTIONLOGEVENTASYNC
            ]
            for event in rejoin_error_events:
                logger().info(f"event type is {event.event_type} and event data is: {event.event_data}")
                output = event.event_data
            logger().info(f"\n\n Event data is: {output} \n\n")
            result = output.strip().split(':')[1].lstrip()
            logger().info(f"\n\n Reason code:{result} \n\n")
            assert result == '53', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address, sl_collections=sl_collections,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

