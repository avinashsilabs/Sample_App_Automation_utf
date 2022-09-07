import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType,
                            RS9116SecurityMode, RS9116PowerSaveProcedureTypes,RS9116JoinFeatureBitMap
                            )
from utf.interfaces import wifi
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
from utf.interfaces.wifi import SecurityMode, WlanError
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
import utf_wiseconnect.interfaces.cli.rs_commands_base
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf.interfaces.cli import CLITransportException
iter_count = 5

def logger():
    return get_logger(__name__)

""" 
This test plan aims to connect the WIFI AP in Enterprise mode
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's) -ASUS
        5. Sniffer -NUC 
        6. Free Radius Server (For now running on NUC)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Verifying EAP Connection in TLS mode
Step3 : Verifying EAP Connection in TTLS mode
Step4: Verifying EAP Connection in PEAPv0 mode
Step5 : Verifying EAP Connection by loading wrong certificate in TLS mode
Step6 : Verifying EAP Connection by loading no certificate in TLS mode
Step7 : Verifying EAP Connection by setting expired date in TLS mode

Author: swathi.pathuri
"""

# this thread used for wifi join
class RunUnicastTraffic:
    def __init__(self, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, device_ip=None, host_ip=None, timeout=100):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.timeout = timeout
        self.device_ip = device_ip
        self.host_ip = host_ip

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)


    def run_tx(self):

        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip,
                                                             host_role="S", protocol=self.protocol,
                                                             time_out=self.timeout)
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        # open socket and send traffic
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            self.host_ip,
            self.device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        time.sleep(10)
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        self.__print_throughput(tp)

    def run_rx(self):
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip,
                                                             host_role="S", protocol=self.protocol,
                                                             time_out=self.timeout)

        self.net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        # open socket and send traffic
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            self.host_ip,
            self.device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        time.sleep(10)
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        self.__print_throughput(tp)


# this thread used for wifi join
class RunMulticastTraffic:
    def __init__(self, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, timeout=100, device_ip=None, host_ip=None, multicast_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.timeout = timeout
        self.multicast_client = multicast_client
        self.device_ip = device_ip
        self.host_ip = host_ip

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_tx(self):

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = \
            self.multicast_client.interfaces.multicast.multicast_params()
        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        self.wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)

        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip,
                                                             host_role="S", protocol=self.protocol,
                                                             time_out=self.timeout, bind_address=multicast_ip)

        self.net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        # open socket and send traffic
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            self.host_ip,
            self.device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        time.sleep(10)
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        self.__print_throughput(tp)

        logger().info("leaving from multicast group")
        self.wifi_dut.interfaces.wifi.leave_multicast_group(ip_version, multicast_ip)

    def run_rx(self):
        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = \
            self.multicast_client.interfaces.multicast.multicast_params()
        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        self.wifi_dut.interfaces.wifi.join_multicast_group(ip_version, multicast_ip)
        # preparing iperf
        self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip, device_ip=multicast_ip,
                                                             host_role="C", protocol=self.protocol,
                                                             time_out=self.timeout, time_to_leave="32", bandwidth="60M")

        # creating results object for sharing between host and dut
        result = Result(self.net_perf_client.interfaces.net_perf.protocol)

        # open socket and start listening
        with self.wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=self.net_perf_client.interfaces.net_perf.protocol,
                port=self.net_perf_client.interfaces.net_perf.client_port,
                device_ip=self.device_ip,
                data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
                time=self.net_perf_client.interfaces.net_perf.client_timeout) as obj:
            # start iperf
            self.net_perf_client.interfaces.net_perf.start()
            # capture device output
            self.wifi_dut.interfaces.wifi.read_from_device(obj,
                                                           self.net_perf_client.interfaces.net_perf.client_timeout)
        time.sleep(10)
        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None, "Throughput not found"
        self.__print_throughput(tp)

        logger().info("leaving from multicast group")
        self.wifi_dut.interfaces.wifi.leave_multicast_group(ip_version, multicast_ip)


# this thread used for wifi join
class WifiEapThread:

    def __init__(self, wifi_sniffer=None, wifi_dut=None,
                 wifi_access_point=None, eap_type="TLS", testcase=None, wifi_client=None,
                 net_perf_client=None, protocol=None, timeout=60,
                 multicast_client=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.eap_type = eap_type
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.timeout = timeout
        self.device_ip = None
        self.host_ip = None
        self.multicast_client = multicast_client
        self.dut_mac_address = None
        self.ap_bssid = None

    def join_eap(self):
        logger().info("Setting roam parameters")
        # enable Roaming
        self.wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
        logger().info("enable rejoin")
        self.wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
        logger().info("Initiating join")
        self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method=self.eap_type, timeout=40)

    def check_connectivity(self, ping_count=60):
        # Get IP through DHCP
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        self.device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip :{self.device_ip}")

        logger().info("Initiating powersave")
        # Initiating power save
        # This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
        # # Enables the bt power save in DUT
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                    RS9116PowerSaveProcedureTypes.FastPowerSave)
        time.sleep(2)
        logger().info("Initiating ping")
        # Initiate ping from third party wifi-client to DUT
        status = ping(self.device_ip, ping_count)
        assert status, "DUT is not responding to ping request from third party device before store configuration"
        logger().info("ping is successful")


    def run_unicast_traffic(self, traffic_type="TX"):
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{self.host_ip}")
        unicast_obj = RunUnicastTraffic(wifi_dut=self.wifi_dut,
                                        wifi_access_point=self.wifi_access_point, wifi_client=self.wifi_client,
                                        net_perf_client=self.net_perf_client, protocol=self.protocol,
                                        device_ip=self.device_ip, host_ip=self.host_ip, timeout=60)
        if traffic_type == "TX":
            unicast_obj.run_tx()

        if traffic_type == "RX":
            unicast_obj.run_rx()

    def run_multicast_traffic(self, traffic_type="TX"):
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{self.host_ip}")
        unicast_obj = RunMulticastTraffic(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                          wifi_client=self.wifi_client, net_perf_client=self.net_perf_client,
                                          protocol=self.protocol, device_ip=self.device_ip,
                                          host_ip=self.host_ip, timeout=60, multicast_client=self.multicast_client)
        if traffic_type == "TX":
            unicast_obj.run_tx()

        if traffic_type == "RX":
            unicast_obj.run_rx()


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, dut_mac_address=None, \
                 ap_bssid=None, conn_status=True, eap_type="TLS"):

        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_bssid = ap_bssid
        self.conn_status = conn_status
        self.eap_type = eap_type

    def verify_sniffer_validation(self):

        validation = True


        beacon_filter = f"(wlan.fc.type_subtype == 0x0008) and wlan.rsn.akms.type == 1 and (wlan.sa == {self.ap_bssid} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter2 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter3 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"

        packet_filter4 = f" (dhcp) && (wlan.addr == {self.ap_bssid}) && (wlan.addr == {self.dut_mac_address})"

        packet_filter5 = f'wlan.sa == {self.dut_mac_address} and ' \
                         f'wlan.fc.pwrmgt == 1 and wlan.fc.type_subtype == 0x0024'

        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        # Validating the de auth frames
        packet_filter7 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x000c'


        logger().info(
            f"Validating beacons"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, beacon_filter)[
            'packet_count'], 'Unable to find beacons in sniffer'

        # logger().info(
        #     f"Validating Probe req(Broadcast)"
        # )
        # assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        #     'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'

        logger().info(
            f"Validating association, eapol from DUT"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '

        logger().info(
            f"Validating association, eapol from AP"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '


        if not self.conn_status:

            # Validating the EAP failure frames
            packet_filter9 = f'wlan.sa == {self.ap_bssid} and wlan.da == {self.dut_mac_address} and eap.code == 4'

            logger().info(
                f"Validating EAP failure frame in sniffer"
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
                'packet_count'], 'Unable to find EAP failure frames sent from AP in sniffer '

        if self.conn_status:
            packet_filter8 = None

            if self.eap_type == "TLS":

                # Validating the EAP failure frames
                packet_filter8 = f'wlan.addr == {self.ap_bssid} and wlan.addr == {self.dut_mac_address} and eap.type == 13'

            if self.eap_type == "TTLS":
                # Validating the EAP failure frames
                packet_filter8 = f'wlan.addr == {self.ap_bssid} and wlan.addr == {self.dut_mac_address} and eap.type == 21'

            if self.eap_type == "PEAP":
                # Validating the EAP failure frames
                packet_filter8 = f'wlan.addr == {self.ap_bssid} and wlan.addr == {self.dut_mac_address} and eap.type == 25'

            if packet_filter8:
                logger().info(
                    f"Validating EAP frames for the method EAP {self.eap_type} in sniffer"
                )
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter8)[
                    'packet_count'], 'Unable to find EAP frames sent from AP in sniffer '

            logger().info(f"Validating QOS  NULL data frames with power management bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
                'packet_count'], 'Unable to find power management bit in QOS null frames in sniffer capture'

            logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
                'packet_count'], 'Unable to find ps polls in sniffer capture'

            # logger().info(f"Validating deauth frames are sent from the device")
            # assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7)[
            #     'packet_count'], 'Unable to find de-auths in sniffer capture'
            logger().info("Successfully validated sniffer packets")





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_C19018(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_C19018"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase)
    eap_obj.join_eap()
    eap_obj.check_connectivity()

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TTLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TTLS_C19019(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TTLS_C19019"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TTLS", testcase=testcase)
    eap_obj.join_eap()
    eap_obj.check_connectivity()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                              eap_type="TTLS")
    verify_sniffer.verify_sniffer_validation()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_PEAPv0_C19020(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_PEAPv0_C19020"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="PEAP", testcase=testcase)
    eap_obj.join_eap()
    eap_obj.check_connectivity()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)


    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                              eap_type="PEAP")
    verify_sniffer.verify_sniffer_validation()




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        # "ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
        # "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C19022(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C19022"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)
    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating join")
    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40)
        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"


    logger().info("Connection failed when no certs loaded")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                                conn_status=False)
    verify_sniffer.verify_sniffer_validation()





@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
        | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)

@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
# EAP Connection in TTS mode with no certificate
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_with_WPA2_EAP_with_expired_cert_TLS_C19023(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                 radius_server):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_cert_TLS_C19023"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                     month_day=1,
                                     month=1, year=1930, week_day=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase)

    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        eap_obj.join_eap()
        assert exc_info.value.error_code == 0x8, "Connection should failed with expired certs"

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("Connection should failed with expired certs")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                                conn_status=False)
    verify_sniffer.verify_sniffer_validation()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost
        | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)

@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
# EAP Connection in TTS mode with no certificate
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_with_WPA2_EAP_with_valid_and_expired_cert_TLS_C19025(wifi_sniffer, wifi_dut, wifi_access_point,
                                                                           radius_server):

    for i in range(0, 2):

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        if i == 0:
            testcase = "test_connectivity_with_WPA2_EAP_with_expired_cert_TLS_C19025"
            validation = True
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

            wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                             month_day=1,
                                             month=1, year=1930, week_day=4)
        else:
            testcase = "test_connectivity_with_WPA2_EAP_with_valid_cert_TLS_C19025"
            validation = True
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
            wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                             month_day=1,
                                             month=1, year=2022, week_day=4)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("enable eap method")
        eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                                wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase)

        logger().info("Initiate connection")

        if i == 0:
            with pytest.raises(WlanError) as exc_info:
                eap_obj.join_eap()
                assert exc_info.value.error_code == 0x8, "Connection should fail when expired certs loaded"

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                      ap_bssid, conn_status=False)
            verify_sniffer.verify_sniffer_validation()
        else:
            eap_obj.join_eap()
            eap_obj.check_connectivity()

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                      ap_bssid)
            verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client |  RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "ca-chain.cert.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_when_wrong_cert_C19024(wifi_sniffer, wifi_dut, wifi_access_point, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_when_wrong_cert_C19024"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)
    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")
    logger().info("Initiating join")
    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS", timeout=40)
        assert exc_info.value.error_code == 0x8, "Connection should fail when wrong certs loaded"

    logger().info("Connection failed when wrong certs loaded")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                              conn_status=False)
    verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client
        | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.TLS_V1,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_v_1_0_C19027(wifi_sniffer, wifi_access_point, wifi_dut, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_v_1_0_C19027"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase)
    eap_obj.join_eap()
    eap_obj.check_connectivity()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the EAP failure frames
    packet_filter9 = f'wlan.addr == {dut_mac_address} and wlan.addr == {ap_bssid} ' \
                     f'and eap and tls.record.version == 0x0301'

    logger().info(
        f"Validating EAP frames TLS version in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find EAP frames with TLS version 1.0 sent'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints
        | RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678', \
                          'protected_management_frame': 'Capable'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_connectivity_in_WPA2_EAP_TLS_PMF_C19026(wifi_sniffer, wifi_access_point, wifi_dut, radius_server):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_PMF_C19026"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_dut.interfaces.wifi.eap_join_ap(wifi_access_point, eap_method="TLS",
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable,
                                         timeout=40)
    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase)
    eap_obj.check_connectivity()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()

    # Validating the assoc req frames with pmf bit
    packet_filter9 = f'(wlan.fc.type_subtype == 0) && (wlan.rsn.capabilities.mfpc == 1) ' \
                     f'and wlan.addr == {dut_mac_address}'

    logger().info(
        f"Validating the assoc req frames with pmf bit in sniffer"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter9)[
        'packet_count'], 'Unable to find assoc req frames with pmf bit'




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client |  RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPAEnterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
def test_GTK_Renewal_WPA_EAP_Multicast_C19029(radius_server, multicast_client, net_perf_client, protocol,
                                                  wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_GTK_Renewal_WPA_EAP_Multicast_C19029"

    wifi_access_point.interfaces.wifi.set_group_key_renewal_period_ap(gtk=30)
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase,
                            wifi_client=wifi_client, net_perf_client=net_perf_client, protocol=protocol, timeout=100,
                            multicast_client=multicast_client)
    eap_obj.join_eap()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj.check_connectivity(ping_count=10)

    eap_obj.run_multicast_traffic(traffic_type="TX")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client |  RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_GTK_Renewal_WPA2_EAP_TTLS_C19030(radius_server, multicast_client, net_perf_client, protocol,
                                                  wifi_sniffer, wifi_dut, wifi_client, wifi_access_point,utf_constants):
    testcase = "test_GTK_Renewal_WPA2_EAP_TTLS_C19030"

    wifi_access_point.interfaces.wifi.set_group_key_renewal_period_ap(gtk=30)
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TTLS", testcase=testcase,
                            wifi_client=wifi_client, net_perf_client=net_perf_client, protocol=protocol, timeout=100)
    eap_obj.join_eap()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj.check_connectivity()

    duration = utf_constants.get("time_duration")

    time.sleep(duration)
    logger().info(f"running for long run duration for {duration} need to pass from harness")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client |  RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPAEnterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_GTK_Renewal_WPA_EAP_unicast_C70607(radius_server, net_perf_client, protocol,
                                             wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_GTK_Renewal_WPA_EAP_unicast_C70607"

    wifi_access_point.interfaces.wifi.set_group_key_renewal_period_ap(gtk=30)
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase,
                            wifi_client=wifi_client, net_perf_client=net_perf_client, protocol=protocol, timeout=100)
    eap_obj.join_eap()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj.check_connectivity(ping_count=10)

    eap_obj.run_unicast_traffic(traffic_type="TX")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client |  RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_GTK_Renewal_WPA2_EAP_unicast_C70609(radius_server, net_perf_client, protocol,
                                             wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_GTK_Renewal_WPA2_EAP_unicast_C70609"

    wifi_access_point.interfaces.wifi.set_group_key_renewal_period_ap(gtk=30)
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase,
                            wifi_client=wifi_client, net_perf_client=net_perf_client, protocol=protocol, timeout=100)
    eap_obj.join_eap()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj.check_connectivity(ping_count=10)

    eap_obj.run_unicast_traffic(traffic_type="RX")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client |  RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "disassociated", "clear_certs"])
def test_GTK_Renewal_WPA2_EAP_Multicast_C70608(radius_server, multicast_client, net_perf_client, protocol,
                                               wifi_sniffer, wifi_dut, wifi_client, wifi_access_point):
    testcase = "test_GTK_Renewal_WPA2_EAP_Multicast_C70608"

    wifi_access_point.interfaces.wifi.set_group_key_renewal_period_ap(gtk=30)
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    logger().info("enable eap method")
    eap_obj = WifiEapThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut,
                            wifi_access_point=wifi_access_point, eap_type="TLS", testcase=testcase,
                            wifi_client=wifi_client, net_perf_client=net_perf_client, protocol=protocol, timeout=100,
                            multicast_client=multicast_client)
    eap_obj.join_eap()

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    eap_obj.check_connectivity(ping_count=10)

    eap_obj.run_multicast_traffic(traffic_type="RX")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = SnifferValidationProcess(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
    verify_sniffer.verify_sniffer_validation()






