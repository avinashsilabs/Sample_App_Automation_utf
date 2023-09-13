import pytest
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap,
                                            Si91xOperatingMode,
                                            Si91xCustomFeatureBitMap,
                                            Si91xConfigFeatureBitMap,
                                            Si91xTCPIPFeatureBitMap,
                                            Si91xExtCustomFeatureBitMap,
                                            Si91xExtTCPIPFeatureBitMap,
                                            Si91xCertificateType,
                                            Si91xSecurityMode, Si91xPowerSaveProcedureTypes, Si91xJoinFeatureBitMap
                                            )
from utf.utils.logger import get_logger
import time
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType

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

    Author: M.Harshitha 

"""


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None, \
                 ap_mac_address=None, conn_status=True, eap_type="TLS", sniffer_filter=None):

        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.sniffer_filter = sniffer_filter

    def verify_sniffer_validation(self):
        if self.wifi_access_point.interfaces.wifi.security == SecurityMode.WPAEnterprise:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address, da_addr=self.dut_mac_address,
                filter_name='beacon_wpa2_entr_wfa_check')
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        else:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check')
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address, filter_name='assoc_req_resp_eapol_4_way_handshake')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address, filter_name='power_mgmt_bit')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter3}\n\n")
        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address, filter_name='null_data_powersave')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter4}\n\n")
        if self.conn_status:
            packet_filter5 = None
            if self.eap_type == "TLS":
                packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    da_addr=self.ap_mac_address,
                    sa_addr=self.dut_mac_address, filter_name='eap_type_tls_verification')
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter5}\n\n")
            if self.eap_type == "TTLS":
                packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    da_addr=self.ap_mac_address,
                    sa_addr=self.dut_mac_address, filter_name='eap_type_tls_verification')
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter5}\n\n")
            if self.eap_type == "PEAP":
                packet_filter5 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    da_addr=self.ap_mac_address,
                    sa_addr=self.dut_mac_address,
                    filter_name='eap_type_peap_verification')
                logger().info(f"\n\n\n Sniffer Filter = {packet_filter5}\n\n")
            if packet_filter5:
                logger().info(f"Validating EAP frames for the method EAP {self.eap_type} in sniffer")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
                'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        if not self.conn_status:
            packet_filter6 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                da_addr=self.ap_mac_address,
                sa_addr=self.dut_mac_address, filter_name='eap_conn_4')
            logger().info(f"\n\n\n Sniffer Filter = {packet_filter6}\n\n")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)[
                'packet_count'], \
                'Unable to find EAP failure frames sent from AP in sniffer '

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find beacons in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'


class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, net_perf_client=None, protocol=None,
                 sl_collections=None, test_name=None, eap_type_tls=True, eap_type_ttls=True, eap_type_peap=True,
                 eap_type_tls_no_cert=True, test_case_no=None, set_rtc=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.eap_type_tls = eap_type_tls
        self.eap_type_ttls = eap_type_ttls
        self.eap_type_peap = eap_type_peap
        self.eap_type_tls_no_cert = eap_type_tls_no_cert
        self.dut_addr = None
        self.device_ip = None
        self.test_case_no = test_case_no
        self.set_rtc = set_rtc

    def run_traffic_tx(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        logger().info("starting the server from Remote device")
        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.device_ip,
                                                             protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=self.device_ip, remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=1000, ttl=60)
        # # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")

    def run_traffic_rx(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=self.device_ip,
                                                             protocol=self.protocol, bandwidth="68M")

        self.net_perf_client.interfaces.net_perf.start()
        logger().info("receiving data from Host")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                            local_ip=self.device_ip, remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                            size=100, ttl=30)
        logger().info("data received is successful")
        time.sleep(3)

    def run(self):
        try:
            if self.eap_type_tls:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut, wifi_access_point=
                self.wifi_access_point, eap_type="TLS")
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                self.wifi_dut.interfaces.wifi.leave()

            if self.eap_type_ttls:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut, wifi_access_point=
                self.wifi_access_point, eap_type="TTLS")
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                self.wifi_dut.interfaces.wifi.leave()

            if self.eap_type_peap:
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut, wifi_access_point=
                self.wifi_access_point, eap_type="PEAP")
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                self.wifi_dut.interfaces.wifi.leave()

            if self.eap_type_tls_no_cert:
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
                self.scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0,
                                                                       ssid=self.wifi_access_point.interfaces.wifi.ssid)
                logger().info(self.scan_results)
                self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
                logger().info(f"******Device mac address**** {self.dut_mac_address}")
                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
                logger().info(f"****AP mac address*****{self.ap_mac_address}")

                if self.test_case_no == 19022:
                    with pytest.raises(WlanError) as exc_info:
                        self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method="TLS", timeout=40)
                        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"
                    logger().info("Connection failed when no certs loaded")

                if self.test_case_no == 19023:
                    with pytest.raises(WlanError) as exc_info:
                        self.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method="TLS", timeout=40)
                        assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"
                    self.wifi_dut.interfaces.wifi.leave()

                if self.test_case_no == 19024:
                    with pytest.raises(WlanError) as exc_info:
                        self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method="TLS", timeout=40)
                        assert exc_info.value.error_code == 0x8, "Connection should fail when wrong certs loaded"
                    logger().info("Connection failed when wrong certs loaded")
                    self.wifi_dut.interfaces.wifi.leave()

            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

            if self.set_rtc:
                self.wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23, month_day=1, month=1, year=1930,
                                                      week_day=4)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_eap_tls_c19018(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                   radius_server, sl_collections, request, net_perf_client, protocol,
                                                   utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap tls method"""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client,
                                     protocol=protocol, eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert=False,
                                     set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                            dut_mac_address, ap_mac_address)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_eap_ttls_c19019(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                    radius_server, sl_collections, request, net_perf_client, protocol,
                                                    utf_constants):
    """ This test case Verifies the wpa2 enterprise connectivity while using eap ttls method"""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client, protocol=protocol, eap_type_tls=False,
                                     eap_type_ttls=True, eap_type_peap=False, sl_collections=sl_collections,
                                     test_name=test_name,
                                     eap_type_tls_no_cert=False, set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"*******Ap Mac Addr********{ap_mac_address}")
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                            dut_mac_address, ap_mac_address)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_eap_peapv0_c19020(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, net_perf_client, protocol,
                                                      utf_constants):
    """ This test case verifies the wpa2 enterprise connectivity while using eap peapv0 method"""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client,
                                     protocol=protocol, eap_type_tls=False, eap_type_ttls=False, eap_type_peap=True,
                                     sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert=False,
                                     set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                            dut_mac_address, ap_mac_address)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_tls_1_0_c19027(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                   radius_server, sl_collections, request, net_perf_client, protocol,
                                                   utf_constants):
    """ This test case verifies the wpa2 enterprise connectivity with tls version 1.0 while using eap tls method"""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client,
                                     protocol=protocol, eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert=False,
                                     set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, sniffer_filter, wifi_access_point,
                                                            dut_mac_address, ap_mac_address)
            sniffer_verification.verify_sniffer_validation()
            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=wifi_thread.dut_addrr['dut_mac_address'],
                da_addr=ap_mac_address, filter_name='eap_tls_cert_verification_1_0')
            logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
                'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_tls_when_no_cert_c19022(wifi_sniffer, wifi_dut, wifi_access_point, radius_server,
                                                            request, utf_constants, sl_collections, net_perf_client,
                                                            protocol):
    """This test case verifies the wpa2 enterprise connectivity when the certificate is not loaded into
        the device while using eap tls."""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, eap_type_tls=False,
                                     eap_type_ttls=False, eap_type_peap=False, test_name=test_name,
                                     eap_type_tls_no_cert=True, test_case_no=19022, set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                            ap_mac_address, conn_status=False)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_with_expired_cert_tls_c19023(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server,
                                                                 request, utf_constants, sl_collections):
    """This test case verifies the wpa2 enterprise connectivity when the Expired Date is set while using EAP TLS"""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, eap_type_tls=False,
                                     eap_type_ttls=False, eap_type_peap=False, test_name=test_name, set_rtc=True,
                                     eap_type_tls_no_cert=True, test_case_no=19023)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                            ap_mac_address, conn_status=False)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "ca-chain.cert.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_eap_tls_when_wrong_cert_c19024(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                   radius_server,
                                                                   request, utf_constants, sl_collections):
    """This test case verifies the wpa2 enterprise connectivity when the wrong certificate is loaded into the device
            while using EAP TLS"""
    try:
        test_name = request.node.name
        iteration = utf_constants.get("iter_count")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, eap_type_tls=False,
                                     eap_type_ttls=False, eap_type_peap=False, test_name=test_name, set_rtc=False,
                                     eap_type_tls_no_cert=True, test_case_no=19024)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        for count in range(0, iteration):
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                            ap_mac_address, conn_status=False)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {

        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPAEnterprise', "passphrase": '12345678', "gtk_int": 30})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_gtk_renewal_wpa_eap_unicast_c70607(wifi_dut, wifi_client, wifi_access_point, request, sl_collections,
                                                     radius_server, net_perf_client, protocol, wifi_sniffer,
                                                     sniffer_filter):
    """This test case verifies the wpa enterprise connectivity and checks the gtk renewal functionality while sending
            unicast data"""
    try:
        test_name = request.node.name
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client,
                                     protocol=protocol, eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert=False,
                                     set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_mac_address}")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                        ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', "gtk_int": 30})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_gtk_renewal_wpa2_eap_unicast_c70609(wifi_dut, wifi_client, wifi_access_point, request, sl_collections,
                                                      radius_server, net_perf_client, protocol, wifi_sniffer,
                                                      sniffer_filter):
    """This test case verifies the wpa2 enterprise connectivity and checks the gtk renewal functionality while sending unicast data"""
    try:
        test_name = request.node.name
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_client=wifi_client, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client,
                                     protocol=protocol, eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert=False,
                                     set_rtc=False)
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_mac_address}")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_rx()
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                        ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', "gtk_int": 30})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_gtk_wpa2_eap_ttls_c19030(wifi_dut, wifi_client, wifi_access_point, request, sl_collections,
                                           radius_server, net_perf_client, protocol, wifi_sniffer, sniffer_filter,
                                           utf_constants):
    """This test case verifies the wpa2 enterprise connectivity while using eap ttls method when the gtk renewal period is 30 seconds"""
    try:
        test_name = request.node.name
        duration = utf_constants.get("time_duration")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     net_perf_client=net_perf_client,
                                     protocol=protocol, eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert=False,
                                     set_rtc=False)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        dut_mac_address = wifi_thread.dut_addrr['dut_mac_address']
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr {ap_mac_address}")
        time.sleep(duration)
        logger().info(f"running for long run duration for {duration} need to pass from harness")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                        ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', \
                                               'protected_management_frame': 'Capable'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_connectivity_wpa2_tls_pmf_c19026(utf_constants, wifi_sniffer, wifi_access_point, wifi_dut,
                                                   radius_server,
                                                   request, sl_collections):
    """ This test case verifies the WPA2 Enterprise Connectivity with PMF enabled while using EAP TLS Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        # wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS",
        #                                  join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable,timeout=40)
        dut_addrr = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                        associated=wifi_dut.interfaces.wifi.associated,
                                                        ping_after_power_save=False)
        logger().info(f"device_ip, device_mac : {dut_addrr['device_ip']}, {dut_addrr['dut_mac_address']}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_mac_address}")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(10)
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.RealTimeClockFromHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_conn_with_wpa2_eap_with_valid_and_expired_cer_tls_c19025(wifi_dut, wifi_client, wifi_access_point,
                                                                           request, sl_collections,
                                                                           radius_server, wifi_sniffer, sniffer_filter):
    """This test case verifies the WPA2 Enterprise Connectivity when the Valid / Expired Date is set while using EAP TLS Method"""
    try:
        for i in range(0, 2):
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"DUT Mac addr{dut_mac_address}")
            if i == 0:
                test_name = request.node.name
                wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23, month_day=1, month=1, year=1930,
                                                 week_day=4)
            else:
                test_name = request.node.name
                wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
                wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
                wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23, month_day=1, month=1, year=1930,
                                                 week_day=4)
                scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
                logger().info(scan_results)
            if i == 0:
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initiating join")
                    wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40)
                    assert exc_info.value.error_code == 0x8, "Connection should fail when expired certs loaded"
                wifi_sniffer.interfaces.capture.stop_capture()
                sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                                ap_mac_address, conn_status=False)
                sniffer_verification.verify_sniffer_validation()
            else:
                dut_addr = sl_collections.join_to_eap_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                                              eap_type="TLS")
                logger().info(f"device_ip, device_mac : {dut_addr['device_ip']}, {dut_addr['dut_mac_address']}")
                wifi_dut.interfaces.wifi.leave()
                time.sleep(10)
                wifi_sniffer.interfaces.capture.stop_capture()
                sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                                ap_mac_address)
                sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)