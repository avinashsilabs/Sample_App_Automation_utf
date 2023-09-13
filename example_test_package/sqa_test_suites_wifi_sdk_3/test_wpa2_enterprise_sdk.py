import pytest

from utf_wiseconnect_3.tests.devices.si91x import (si91xCoexMode, si91xPowerSaveModes, si91xFeatureBitMap,
                                            si91xCustomFeatureBitMap, si91xConfigFeatureBitMap,si91xTCPIPFeatureBitMap,
                                            si91xExtCustomFeatureBitMap,si91xExtTCPIPFeatureBitMap,
                                            si91xCertificateType,si91xSecurityMode, si91xPowerSaveProcedureTypes, si91xJoinFeatureBitMap,
                                            si91xAsyncEventType,SocketOptions,SocketType,Cipher,si91xOperatingMode
                                            )

from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
import time
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from test_wlan_sta_enterprise_sdk import SnifferValidationProcess

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

class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, net_perf_client=None, protocol=None,
                 sl_collections=None, test_name=None, sniffer_filter=None, wifi_sniffer=None, eap_type_tls=True, eap_type_ttls=True,
                 eap_type_peap=True,
                  test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.test_case_no = test_case_no
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.eap_type_tls = eap_type_tls
        self.eap_type_ttls = eap_type_ttls
        self.eap_type_peap = eap_type_peap

    def run_traffic_tx(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.device_ip, protocol=self.protocol)
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            local_ip=self.device_ip, remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                            size=1460, ttl=30, throughput_type=1, qos=0)
        # # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer successful")

    def run_traffic_rx(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=self.device_ip, protocol=self.protocol)
        logger().info(f"***** starting iperf ******")
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("receiving data from Host")
        # open socket and listen for data
        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                            local_ip=self.device_ip, remote_ip=host_ip,
                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                            size=1460, ttl=30, throughput_type=3, qos=0)
        logger().info("data received is successful")
        
    def verification_tls_1_2_version(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                        sa_addr=dut_mac_address, da_addr=ap_mac_address,
                        filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

    def verification_tls_1_0_version(self):
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_mac_address()
        ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                                    sa_addr=dut_mac_address, da_addr=ap_mac_address,
                                    filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    
    def run(self):
        try:
            if self.eap_type_tls:
                self.dut_addr = self.sl_collection.join_to_eap_network(wifi_dut=self.wifi_dut, wifi_access_point=
                self.wifi_access_point, eap_type="TLS")
                logger().info(f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                time.sleep(10)

            if self.eap_type_ttls:
                self.dut_addr = self.sl_collection.join_to_eap_network(wifi_dut=self.wifi_dut, wifi_access_point=
                self.wifi_access_point, eap_type="TTLS")
                logger().info(f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                time.sleep(10)

            if self.eap_type_peap:
                self.dut_addr = self.sl_collection.join_to_eap_network(wifi_dut=self.wifi_dut, wifi_access_point=
                self.wifi_access_point, eap_type="PEAP")
                logger().info(f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
                time.sleep(10)

            if self.test_case_no == 113771:
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method="TLS", timeout=40)
                assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"
                logger().info("Connection failed when expired certs loaded")
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initiate ip command")
                    self.wifi_dut.interfaces.wifi.start_ip(timeout=20)
                    assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

            if self.test_case_no == 113772:
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method="TTLS", timeout=40)
                assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initiate ip command")
                    self.wifi_dut.interfaces.wifi.start_ip(timeout=20)
                    assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

            if self.test_case_no == 113773:
                with pytest.raises(WlanError) as exc_info:
                    self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method="PEAP", timeout=40)
                assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"
                with pytest.raises(WlanError) as exc_info:
                    logger().info("Initiate ip command")
                    self.wifi_dut.interfaces.wifi.start_ip(timeout=20)
                    assert exc_info.value.error_code == 0x21, "ip command should failed 0x21 error"

            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in thread: {str(e)} ****\n\n")
            raise e

            
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": si91xExtCustomFeatureBitMap.FeatureLowPower | si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp | si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_2_c113765(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                  sniffer_filter, sl_collections, net_perf_client, protocol, request,
                                                  radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
          is loaded using the in TLs version 1.2"""
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                     eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        wifi_thread.verification_tls_1_2_version()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": si91xExtCustomFeatureBitMap.FeatureLowPower | si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp | si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_ttls_1_2_c113766(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                   sniffer_filter, sl_collections, net_perf_client, protocol, request,
                                                   radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method  when the certificate
    is loaded using the in TLs version 1.2"""
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                     eap_type_tls=False, eap_type_ttls=True, eap_type_peap=False,
                                     sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                  ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        wifi_thread.verification_tls_1_2_version()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": si91xExtCustomFeatureBitMap.FeatureLowPower | si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp | si91xConfigFeatureBitMap.TLS_V2,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_peapv0_1_2_c113767(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                     sniffer_filter, sl_collections, net_perf_client, protocol, request,
                                                     radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP PEAPv0 Method  when the certificate
        is loaded using the in TLs version 1.2"""
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                     eap_type_tls=False, eap_type_ttls=False, eap_type_peap=True,
                                     sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        wifi_thread.verification_tls_1_2_version()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
        
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": si91xExtCustomFeatureBitMap.FeatureLowPower | si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp | si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_0_c113775(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                  sniffer_filter, sl_collections, net_perf_client, protocol, request,
                                                  radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in TLs version 1.0 """
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                     eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_rx()
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                  ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        wifi_thread.verification_tls_1_0_version()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": si91xExtCustomFeatureBitMap.FeatureLowPower | si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp | si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_ttls_1_0_c113776(wifi_sniffer, wifi_dut, wifi_access_point, wifi_client,
                                                        sniffer_filter, sl_collections, net_perf_client, protocol, request,
                                                        radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method  when the certificate
    is loaded using the in TLs version 1.0"""
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                     eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                  ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        wifi_thread.verification_tls_1_0_version()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | si91xCustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": si91xExtCustomFeatureBitMap.FeatureLowPower | si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp | si91xConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_peapv0_1_0_c113777(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                     sniffer_filter, sl_collections, net_perf_client, protocol, request,
                                                     radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP PEAPv0 Method when the certificate
        is loaded using the in TLs version 1.0"""
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                     net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                     eap_type_tls=True, eap_type_ttls=False, eap_type_peap=False,
                                     sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        wifi_dut.interfaces.wifi.leave()
        logger().info("stopping capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                  ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        wifi_thread.verification_tls_1_0_version()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": si91xExtCustomFeatureBitMap.Default | si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_ttls_no_cert_c113780(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                           sniffer_filter, sl_collections, net_perf_client, protocol,
                                                           request, radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
        is not loaded into the device """
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                        net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                        eap_type_tls=False, eap_type_ttls=True, eap_type_peap=False,
                                        sl_collections=sl_collections)
        wifi_thread.start()
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_rx()
        logger().info("Disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                        ap_mac_address)
        sniffer_verification.verify_sniffer_validation()()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": si91xExtCustomFeatureBitMap.Default | si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_peapv0_no_cert_c113781(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer,
                                                             sniffer_filter, sl_collections, net_perf_client, protocol,
                                                             request, radius_server):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP PEAPv0 Method when the certificate
        is not loaded into the device """
    try:
        test_name = request.node.name
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                  net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                  eap_type_tls=False, eap_type_ttls=False, eap_type_peap=True,
                                  sl_collections=sl_collections)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_thread.run_traffic_tx()
        logger().info("Disconnect from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": si91xExtCustomFeatureBitMap.Default | si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_eap_tls_no_cert_c113779(self, wifi_dut, wifi_access_point, utf_constants, wifi_client,
                                                          wifi_sniffer, protocol, sniffer_filter, sl_collections,
                                                          net_perf_client, radius_server, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is not loaded into the device """
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        # wifi_dut.interfaces.wifi.load_certificate(cert_type=1, cert_index=0)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                 beacon_missed_count=40,
                                                                 first_time_retry_enable=0)
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        for count in range(0, iter_count):
            logger().info("scanning for AP")
            scan_results = self.sl_collectons.scan(self.wifi_dut)
            logger().info(scan_results)
            logger().info("Getting the DUT mac")
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                      net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                      eap_type_tls=False, eap_type_ttls=False, eap_type_peap=False, test_case_no=113771,
                                      sl_collections=sl_collections)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)
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
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.RealTimeClockFromHost | si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": si91xExtCustomFeatureBitMap.Default | si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date_eap_tls_c113771(self, wifi_dut, wifi_access_point, utf_constants,
                                                               wifi_client, wifi_sniffer, sniffer_filter, radius_server,
                                                               net_perf_client, protocol, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while using EAP TLS Method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        for count in range(0, iter_count):
            # wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23, month_day=1, month=1, year=1930, week_day=4)
            logger().info("scanning for AP")
            scan_results = self.sl_collectons.scan(self.wifi_dut)
            logger().info(scan_results)
            logger().info("Getting the DUT mac")
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                        net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                        eap_type_tls=False, eap_type_ttls=False, eap_type_peap=False, test_case_no=113771,
                                        sl_collections=sl_collections)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)
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
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.RealTimeClockFromHost | si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": si91xExtCustomFeatureBitMap.Default | si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date__ttls_c113772(self, wifi_dut, wifi_access_point, utf_constants,
                                                             wifi_client, wifi_sniffer, sniffer_filter, radius_server,
                                                             net_perf_client, protocol, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while using EAP TTLS Method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        for count in range(0, iter_count):
            # wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23, month_day=1, month=1, year=1930, week_day=4)
            logger().info("scanning for AP")
            scan_results = self.sl_collectons.scan(self.wifi_dut)
            logger().info(scan_results)
            logger().info("Getting the DUT mac")
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                      net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                      eap_type_tls=False, eap_type_ttls=False, eap_type_peap=False, test_case_no=113772,
                                      sl_collections=sl_collections)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)
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
        "oper_mode": si91xOperatingMode.EAPWiFiClient,
        "coex_mode": si91xCoexMode.WLAN | si91xCoexMode.BLE,
        "features": si91xFeatureBitMap.OpenMode | si91xFeatureBitMap.ULPGPIOHandshake | si91xFeatureBitMap.Aggregation,
        "tcpip_features": si91xTCPIPFeatureBitMap.DHCPv4Client | si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": si91xCustomFeatureBitMap.RealTimeClockFromHost | si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": si91xExtCustomFeatureBitMap.Default | si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": si91xExtTCPIPFeatureBitMap.WaitForSocketClose | si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date_peap_c113773(self, wifi_dut, wifi_access_point, utf_constants,
                                                            wifi_client, wifi_sniffer, sniffer_filter, radius_server,
                                                            net_perf_client, protocol, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while using EAP PEAP Method"""
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP Mac Addr: {ap_mac_address}")
        for count in range(0, iter_count):
            # wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23, month_day=1, month=1, year=1930, week_day=4)
            logger().info("scanning for AP")
            scan_results = self.sl_collectons.scan(self.wifi_dut)
            logger().info(scan_results)
            logger().info("Getting the DUT mac")
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_client=wifi_client,
                                      net_perf_client=net_perf_client, protocol=protocol, test_name=test_name,
                                      eap_type_tls=False, eap_type_ttls=False, eap_type_peap=False, test_case_no=113773,
                                      sl_collections=sl_collections)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer, wifi_access_point, dut_mac_address,
                                                            ap_mac_address, conn_status=False)
            sniffer_verification.verify_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)