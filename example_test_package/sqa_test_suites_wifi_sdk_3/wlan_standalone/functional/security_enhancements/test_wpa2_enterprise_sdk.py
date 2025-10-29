import time
import pytest
from threading import Thread
from utf.utils.thread_base import ThreadBase
from random import randint
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap,
                                                   Si91xOperatingMode,
                                                   Si91xCustomFeatureBitMap,
                                                   Si91xConfigFeatureBitMap,
                                                   Si91xTCPIPFeatureBitMap,
                                                   Si91xExtCustomFeatureBitMap,
                                                   Si91xExtTCPIPFeatureBitMap,
                                                   Si91xCertificateType, Si91xCertIdentifier,
                                                   Si91xPowerSaveProcedureTypes, Si91xJoinFeatureBitMap,
                                                   DeviceConstants, Si91xMqttQos, IEEE802_11W,
                                                   Si91xWebSocketParms
                                                   )
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
import string
import random
import time
import re
from datetime import datetime
import uuid
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.security_enhancements.\
    test_wlan_sta_enterprise_sdk import SnifferValidationProcess
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.websocket.\
    test_websocket_sdk import WebsocketEventHandler
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers

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
def text_generator(size=1000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

class SnifferValidationProcess_pmf_validate:

    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, dut_mac_address=None, \
                 ap_bssid=None, conn_status=True, eap_type="TLS", test_case_no=None, sniffer_filter=None):

        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_bssid = ap_bssid
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.test_case_no = test_case_no
        self.sniffer_filter = sniffer_filter

    def verify_sniffer_validation(self):

        validation = True
        if self.wifi_access_point.interfaces.wifi.security == SecurityMode.WPAEnterprise:
            beacon_filter = f"(wlan.fc.type_subtype == 0x0008) and wlan.wfa.ie.wpa.type == 1 and (wlan.sa == {self.ap_bssid} && wlan.da == ff:ff:ff:ff:ff:ff)"
        else:
            beacon_filter = f"(wlan.fc.type_subtype == 0x0008) and wlan.rsn.akms.type == 1 and (wlan.sa == {self.ap_bssid} && wlan.da == ff:ff:ff:ff:ff:ff)"

        logger().info(
            f"Validating beacons"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, beacon_filter)[
            'packet_count'], 'Unable to find beacons in sniffer'

        packet_filter2 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter3 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"
        # packet_filter4 = f" (dhcp) && (wlan.addr == {self.ap_bssid}) && (wlan.addr == {self.dut_mac_address})"
        packet_filter5 = f'wlan.sa == {self.dut_mac_address} and ' \
                         f'wlan.fc.pwrmgt == 1 and wlan.fc.type_subtype == 0x0024'
        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'
        # Validating the de auth frames
        packet_filter7 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x000c'
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

        if self.test_case_no == "679993" or self.test_case_no == "679994" \
                or self.test_case_no == "679992" or self.test_case_no == "679991" or self.test_case_no == "679990":
            logger().info(f"validating in assoc req for pmf required")
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, ta_addr=self.dut_mac_address,
                filter_name='assoc_req_wpa2_eap_with_pmf_req')

            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                'Unable to validate pmf frames in sniffer'

        if self.test_case_no == "679986" or self.test_case_no == "679988" \
                or self.test_case_no == "679989" or self.test_case_no == "679987":
            logger().info(f"validating in assoc req for pmf capable")
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_mac_address, ta_addr=self.dut_mac_address,
                filter_name='assoc_req_wpa2_eap_with_pmf_cap')

            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], \
                'Unable to validate pmf frames in sniffer'

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

            if self.eap_type == "FAST":
                # Validating the EAP failure frames
                packet_filter8 = f'wlan.addr == {self.ap_bssid} and wlan.addr == {self.dut_mac_address} and eap.type == 43'

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



class Eap_SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, conn_status=True, eap_type="tls", sniffer_filter=None):

        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.sniffer_filter = sniffer_filter

    def verify_eap_failure_sniffer_validation(self):
        if self.wifi_access_point.interfaces.wifi.security == SecurityMode.WPAEnterprise:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_wfa_check')
        else:
            packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.ap_mac_address,
                da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check')

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address,
            filter_name='assoc_req_resp_eapol_4_way_handshake')

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address,
            filter_name='eap_connection_failure')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacons in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find EAP failure frames sent from AP in sniffer '


class FilterPacket:

    def get_beacon_interval(self):

        try:
            packet_filter = "Beacon Interval:"
            beacon_interval_ap = None
            count = 0

            filter_file = open(f'./reports/filter2_file.txt', 'r')
            line = filter_file.readlines()
            for x in line:
                count = count + 1
                if packet_filter in x:
                    beacon_interval_ap = float(x.split(":")[1].split("[Seconds]")[0].strip())
                    beacon_interval_ap = int(beacon_interval_ap * 1000)
                    beacon_interval_ap = beacon_interval_ap - (beacon_interval_ap % 100)
                    print(f'Beacon Interval = {beacon_interval_ap}')
                    break
            filter_file.close()
            return beacon_interval_ap

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def get_dtim_period(self):

        try:
            packet_filter = "DTIM period"
            dtim_period_ap = None
            count = 0

            filter_file = open(f'./reports/filter2_file.txt', 'r')
            line = filter_file.readlines()
            for x in line:
                count = count + 1
                if packet_filter in x:
                    dtim_period_ap = int(x.split(":")[1].strip())
                    print(f'DTIM Period = {dtim_period_ap}')
                    break
            filter_file.close()
            return dtim_period_ap

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


class WPA2Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None, eap_type=None, eap_type_tls_no_cert=None, http_Otaf=None,
                 data_transfer = False, traffic_type = None, protocol = None, time_period = None, data = None,
                 net_perf_client = None, test_case_no = None, multicast_client = None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.eap_type = eap_type
        self.eap_type_tls_no_cert = eap_type_tls_no_cert
        self.dut_addr = None
        self.device_ip = None
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.http_Otaf = http_Otaf
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.protocol = protocol
        self.time_period = time_period
        self.data = data
        self.net_perf_client = net_perf_client
        self.test_case_no = test_case_no
        self.multicast_client = multicast_client

    def run(self):
        try:
            if self.test_case_no == "679987" or self.test_case_no == "679986":
                transfer_type = 1
                protocol = 6
                throughput_type = 1
                size = 1460

            if self.test_case_no == "679988" or self.test_case_no == "679989":
                transfer_type = 1
                protocol = 6
                throughput_type = 3
                size = 1460

            if self.test_case_no == "679992" or self.test_case_no == "679993"or self.test_case_no == "113792":
                transfer_type = 2
                protocol = 17
                throughput_type = 4
                size = 1470

            if self.test_case_no == "679991" or self.test_case_no == "679990" or self.test_case_no == "679994":
                transfer_type = 2
                protocol = 17
                throughput_type = 2
                size = 1470

            if self.eap_type == "tls" or self.eap_type == "ttls" or self.eap_type == "peap" or self.eap_type == "fast" \
                    or self.eap_type == "peapsafe1" or self.eap_type == "peapsafe2":
                if self.test_case_no == "679987" or self.test_case_no == "679986" or self.test_case_no == "679988" or self.test_case_no == "679989":
                    self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                        join_feature_bitmap=IEEE802_11W.Protection_capable |
                                           Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                    self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                            wifi_access_point=self.wifi_access_point,
                                                                            eap_type=self.eap_type,
                                                                            ping_after_power_save=True)
                    logger().info(
                        f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

                    logger().info("DUT successfully connected with AP")
                    time.sleep(2)
                elif self.test_case_no == "679992" or self.test_case_no == "679991" or self.test_case_no == "679993" or self.test_case_no == "679994" or self.test_case_no == "679990":
                    self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=IEEE802_11W.Protection_Required |
                                                                        Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
                    self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                            wifi_access_point=self.wifi_access_point,
                                                                            eap_type=self.eap_type,
                                                                            ping_after_power_save=True)
                    logger().info(
                        f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

                    logger().info("DUT successfully connected with AP")
                    time.sleep(2)
                else:
                    if self.test_case_no == "113792":
                        self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                                wifi_access_point=self.wifi_access_point,
                                                                                eap_type=self.eap_type,
                                                                                ping_after_power_save=True,
                                                                                set_eap_cred=False)
                    else:
                        self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                                wifi_access_point=self.wifi_access_point,
                                                                                eap_type=self.eap_type,
                                                                                ping_after_power_save=True)
                    logger().info(
                        f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")
            if self.eap_type_tls_no_cert == "tls" or self.eap_type_tls_no_cert == "ttls" or self.eap_type_tls_no_cert == "peap":
                self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=self.wifi_access_point.interfaces.wifi.ssid)
                self.wifi_dut.interfaces.wifi.set_eap_credentials()
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                                   security="wpa2_enterprise", uid="user1",
                                                   enc=self.eap_type_tls_no_cert, timeout_ms=1,
                                                   expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
                logger().info(
                    f" Connection failed when expired certificate is loaded into the device,observed error code "
                    f"  0x10008 which is expected")
                self.wifi_dut.interfaces.wifi.start_ip(
                    expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
                logger().info(
                    f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                    f" is expected")

            if self.http_Otaf == "tls":
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type=self.http_Otaf, power_save=False,
                                                                        ping_after_power_save=False)

            if self.data_transfer:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                if self.traffic_type == "TX":
                    if self.test_case_no == "679994":
                        logger().info(f"SENDING MULTICAST DATA")
                        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = self.multicast_client.interfaces.multicast.multicast_params()

                        logger().info(f"DUT joining to the multicast group {multicast_ip}")
                        self.wifi_dut.interfaces.wifi.sl_net_join_multicast_address()

                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=multicast_ip,
                                                                             time_out=60,
                                                                             protocol=self.protocol, time_to_leave="32",
                                                                             bandwidth="60M",
                                                                             host_role="C", bind_address=host_ip)
                        # logger().info(f"Host IP: {host_ip}, Dut IP: {device_ip}, Protocol: {protocol}")
                        logger().info(f"***** starting iperf ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        logger().info(f"***** start listening  ******")
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=multicast_ip, remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            async_socket=1)

                        self.wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()
                        self.net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                        time.sleep(5)

                    else:
                        # starting iperf
                        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol)
                        self.net_perf_client.interfaces.net_perf.start()
                        logger().info("sending data from DUT")
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                            size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                            timeout=timeout + 2)
                        # # get and print throughput
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
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type,
                                                            async_socket=1, timeout=timeout + 2)
                        logger().info("data received is successful")
                        time.sleep(3)

                    elif self.protocol == "TCP":
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                        self.dut_addr['device_ip'], protocol=self.protocol)

                    def start_client():
                        time.sleep(1)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    # open socket and listen for data
                    timeout = 150
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        async_socket=1, timeout=timeout + 2)
                    client_thread1.join()
                    logger().info("data received is successful")
                    time.sleep(3)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_expired_date_eap_tls_c113771(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                               sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set
            while using EAP TLS Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1930)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert="tls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_expired_date_ttls_c113772(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                            sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while
                using EAP TTLS Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1930)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="ttls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer,
                                                                sniffer_filter=sniffer_filter,
                                                                wifi_access_point=wifi_access_point,
                                                                dut_mac_address=dut_mac_address,
                                                                ap_mac_address=ap_mac_address)
            sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_expired_date_peap_c113773(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                            sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity when the expired date is set while
                            using EAP PEAP Method"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hours=23, day=1, month=1, weekday=4, year=1930)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="peap")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
            sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer,
                                                                sniffer_filter=sniffer_filter,
                                                                wifi_access_point=wifi_access_point,
                                                                dut_mac_address=dut_mac_address,
                                                                ap_mac_address=ap_mac_address)
            sniffer_verification.verify_eap_failure_sniffer_validation()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_no_cert_c113779(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                          sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
            is not loaded into the device """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        # wifi_dut.interfaces.wifi.set_eap_credentials()
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name, eap_type_tls_no_cert="tls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case duplicate of C113857")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
def test_wifi_sdk_wpa2_enterprise_eap_ttls_no_cert_c113780(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                           sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
            is not loaded into the device """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="ttls")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.skip("Test case duplicate of C113855")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
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
def test_wifi_sdk_wpa2_enterprise_eap_peap_no_cert_c113781(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                           sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
            is not loaded into the device """
    try:
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name,
                                         eap_type_tls_no_cert="peap")
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_eap_failure_sniffer_validation()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_ttls_1_0_c113776(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in TTLs version 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_peap_1_0_c113777(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in peap version 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_2_c113765(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in tls version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_peap_1_2_c113767(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in peap version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_ttls_1_2_c113766(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TTLS Method when the certificate
        is loaded using the in tls version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1460, ttl=30, throughput_type=3, qos=0, async_socket=0)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_0_c113775(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
        is loaded using the in TLs version 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1460, ttl=30, throughput_type=3, qos=0, async_socket=0)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": [("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"),
                    ("ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START")]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_three_ssl_connection_wpa2_enterprise_eap_c113797(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter,
                                                                   radius_server, sl_collections, request, ssl_server):
    """ This test case verifies the three ssl socket connectivity in WPA2 Enterprise between the dut and the remote
        server """
    try:
        ping_count = 10
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, http_Otaf="tls")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("....Pinging DUT after power-save....")
        status = ping(device_ip, ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        port2 = ssl_server.interfaces.ssl.config['device_port2']
        port3 = ssl_server.interfaces.ssl.config['device_port3']
        ssl_server.interfaces.ssl.start_server(port=port1)
        ssl_server.interfaces.ssl.start_server(port=port2)
        ssl_server.interfaces.ssl.start_server(port=port3)
        server_ip = ssl_server.interfaces.ssl.server_ip
        for sock_count in range(0, 3):
            # Open ssl client socket in the DUT
            sock = wifi_dut.interfaces.wifi.socket()
            assert sock == sock_count, f"Sock ID must be {sock_count} but received {sock}"
            # Enable ssl option for socket opened
            wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
            if sock_count == 0:
                socket_port = port1
                local_port = randint(5001, 20000)
            elif sock_count == 1:
                socket_port = port2
                local_port = randint(20001, 40000)
            else:
                socket_port = port3
                local_port = randint(40001, 60000)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        socket_no = [1, 2, 3]
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            for socket in socket_no:
                buffer_length = 100
                # The api returns 100 bytes of random data
                data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
                if socket < 4:
                    logger().info(f"Sending data {data} over socket_no->{socket - 1}")
                    # DUT sends 100 bytes of data over ssl socket
                    socket_number = socket - 1
                    wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_number, data=data)
                    time.sleep(1)
                    # SSL server receives the data over ssl socket
                    server_socket_no = socket
                    data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
                    logger().info(f"Data received on remote socket opened is {data_receive}")
                    assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
                    logger().info("Data sent by DUT and received on server is matching\n\n")
        for sock_count in range(0, 3):
            logger().info(f"Closing socket_id->{sock_count}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_count)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_mqtt_wpa2_enterprise_c113795(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                               radius_server, sl_collections, request, utf_constants,
                                               mqtt_server, mqtt_client):
    """ This test case verifies the Mqtt connectivity in WPA2 Enterprise """
    try:
        test_name = request.node.name
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        qos = Si91xMqttQos.QOS1
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.mqtt.set_advanced_mqtt_client_configuration(client_id="Si91x_mqtt_client", qos=1)
        logger().info(".....DUT connects to MQTT server.....")
        wifi_dut.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info(".....MQTT Client connects to MQTT server.....")
        mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(server=mqtt_server.interfaces.mqtt)
        logger().info("MQTT Client subscribes to the topic")
        time.sleep(5)
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(5)
        logger().info("DUT subscribes to the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic=topic, qos=Si91xMqttQos.QOS1)
        time.sleep(5)
        logger().info("DUT publishes message over the topic")
        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic=topic, message=message, qos=Si91xMqttQos.QOS1, timeout=20)
        time.sleep(5)
        msgs = []
        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            time.sleep(0.1)
            msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
            if len(msgs) == 1:
                break
        assert len(msgs) == 1, "No message is received by mqtt-client"
        assert msgs[0].topic == topic, "No message received by mqtt-client on subscribed topic"
        assert msgs[0].qos == Si91xMqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
        assert msgs[0].payload.decode() == message, "No message is received by mqtt-client on subscribed topic or " \
                                                    "message received is wrong"
        logger().info("....Unsubscribing from the topic....")
        wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic=topic)
        logger().info("Disconnecting from MQTT Server")
        wifi_dut.interfaces.wifi.mqtt_client_disconnect()
        time.sleep(1)
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_ssl_socket_connection_in_wpa2_enterprise_c113793(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter, radius_server, sl_collections,
                                                                   request, ssl_server):
    """ This test case verifies the ssl socket connectivity in WPA2 Enterprise between the dut and the remote
        server """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        socket_port = port1
        local_port = randint(5001, 20000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            ssl_server.interfaces.ssl.send_data(1, pkt_count, buffer_length, message=tx_buffer)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=50, async_timeout=50)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_otaf_wpa2_enterprise_c113803(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                    sniffer_filter, radius_server, sl_collections, request,
                                                    http_server):
    """ This test case verifies the http otaf in wpa2 enterprise"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        fw_version_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {fw_version_before_upgrade} ***")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, http_Otaf="tls")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("checking server stats....")
        status_http = http_server.interfaces.http.started
        assert status_http, 'Server is inactive'
        logger().info(f'http server state is {status_http}')
        logger().info("fetching server ip....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"server ip is {host_ip}")
        wifi_dut.interfaces.wifi.firmware_upgrade(flags=0, ip_address=host_ip, port=80, host_name=host_ip)
        logger().info(f"*** resetting the device after successful upgradation****")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="eap", config_required=True, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_version_after_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version after upgrade = {fw_version_after_upgrade} ***")
        logger().info(f"\n\n ***firmware versions before otaf:{fw_version_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_version_after_upgrade}")
        assert fw_version_before_upgrade != fw_version_after_upgrade, f"firmware versions should not match after loading" \
                                                                      f" firmware through otaf"
        logger().info(f"\n ***firmware versions not matched after loading"
                      f" firmware through otaf\n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac_address,
            da_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacons in sniffer'
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_otaf_wpa2_enterprise_c113804(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                     sniffer_filter, radius_server, sl_collections, request,
                                                     http_server):
    """ This test case verifies the https otaf in wpa2 enterprise"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        fw_version_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {fw_version_before_upgrade} ***")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, http_Otaf="tls")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("checking server stats....")
        status_http = http_server.interfaces.http.started
        assert status_http, 'Server is inactive'
        logger().info(f'http server state is {status_http}')
        logger().info("fetching server ip....")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"server ip is {host_ip}")
        time.sleep(5)
        wifi_dut.interfaces.wifi.firmware_upgrade(flags=1, ip_address=host_ip, port=443, host_name=host_ip)
        logger().info(f"*** resetting the device after successful upgradation****")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(30)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(mode="eap", config_required=True, load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True
        fw_version_after_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version after upgrade = {fw_version_after_upgrade} ***")
        logger().info(f"\n\n ***firmware versions before otaf:{fw_version_before_upgrade}"
                      f" firmware version after loading through otaf :{fw_version_after_upgrade}")
        assert fw_version_before_upgrade != fw_version_after_upgrade, f"firmware versions should not match after loading" \
                                                                      f" firmware through otaf"
        logger().info(f"\n ***firmware versions not matched after loading"
                      f" firmware through otaf\n")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_mac_address,
            da_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='beacon_wpa2_entr_akms_check')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacons in sniffer'
        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SNTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_sntp_connection_wpa2_enterprise_eap_tls_c113796(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                  sniffer_filter, radius_server, sl_collections,
                                                                  request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS method and checking
            the sntp functionality"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces.wifi.sntp_client_start()
        ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
        logger().info(f'\n\n SNTP server address = {ip_version}, \n {sntp_method},\n {sntp_server_address}\n\n')
        times, date = wifi_dut.interfaces.wifi.sntp_get_time_data()
        logger().info(f'*** Time is {times} ***')
        logger().info(f'*** Date is {date} ***')
        wifi_dut.interfaces.wifi.sntp_client_stop()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.DNSClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_aws_connection_wpa2_enterprise_eap_tls_c113794(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                 sniffer_filter, radius_server, sl_collections,
                                                                 request):
    """ This test case verifies the aws connection in WPA2 Enterprise Connectivity"""
    try:
        domain_name = "a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        aws_port = 8883
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        aws_server_ip = wifi_dut.interfaces.wifi.dns_get(domain_name, query_timeout=120000, timeout=30)
        server_ip = aws_server_ip.strip().decode()
        logger().info(f"aws_server_ip {server_ip}")
        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_addr['device_ip'], server_port=aws_port,
                                      timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=aws_port)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wlan_get_stats_wpa2_enterprise_c113800(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         radius_server, sl_collections, request, utf_constants):
    """ Test case verifies the device is able to get the wireless statistics in station mode"""

    try:
        test_name = request.node.name
        beacon_interval_obj = FilterPacket()
        dtim_period_obj = FilterPacket()
        packet_filter3 = "    Type/Subtype: Beacon (0x0008)"
        validation = True

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        operating_mode, dtim_period, ideal_beacon_info, busy_beacon_info, busy_interval = (
            wifi_dut.interfaces.wifi.get_wifi_operational_stats(timeout=15))

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

        packet_filter = f'(wlan.ssid == "{wifi_access_point.interfaces.wifi.ssid}") and (wlan.fc.type_subtype == 0x0008)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter, packet_filter3)[
            'packet_count']

        beacon_interval_ap = beacon_interval_obj.get_beacon_interval()
        if beacon_interval_ap is None:
            logger().info(f'Unable to find Beacon Interval={beacon_interval_ap}')
            assert False
        else:
            logger().info(f'\n\n *** Beacon Interval ={beacon_interval_ap} *** \n')

        dtim_period_ap = dtim_period_obj.get_dtim_period()
        if dtim_period_ap is None:
            logger().info(f'Unable to find DTIM Period={dtim_period_ap}')
            assert False
        else:
            logger().info(f'\n\n *** DTIM Period ={dtim_period_ap} *** \n')

        logger().info(
            f"\n\n Access point Beacon interval -> {beacon_interval_ap},  DTIM period-> {dtim_period_ap} \n\n "
            f"\n\n DUT Beacon interval -> {busy_interval},  DTIM period-> {dtim_period}\n\n")

        assert operating_mode == '2', "Operating mode is not matching, expected is 2"

        assert busy_interval == f"{beacon_interval_ap}", \
            f"AP beacon interval received in wlan stats and actual beacon " \
            f"interval of connected AP is not matched," \
            f"expected is {beacon_interval_ap}. But observed {busy_interval} "

        assert dtim_period == f"{dtim_period_ap}", f"DTIM period received in wlan stats and actual DTIM " \
                                                   f"interval of connected AP is not matched, e" \
                                                   f"expected is {dtim_period_ap}. But observed {dtim_period} "

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)

        sniffer_verification.verify_sniffer_validation()

        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.RsaKeyWith4096Support | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user_4096.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'wifi-user_4096.pem', "certificate_file": 'wifi-user_4096.pem',
                                   "ca_file": 'wifi-user_4096.pem'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_with_4k_length_c113876(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request, utf_constants,
                                                             net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the 4096 Length
        certificates were loaded """

    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)

        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()

        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.RsaKeyWith4096Support | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
   }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'wifi-user_4096.pem', "certificate_file": 'wifi-user_4096.pem',
                                   "ca_file": 'wifi-user_4096.pem'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_with_individual_4k_length_c113877(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request, utf_constants,
                                                             net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the Individual
    4096 Length certificates were loaded """

    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["privatekey_4096.pem", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["publickey_4096.pem", "SL_NET_PUBLIC_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["cas_4096.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)

        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()

        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'wifi-user.pem', "certificate_file": 'wifi-user.pem',
                                   "ca_file": 'wifi-user.pem'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_with_individual_cert_c113783(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request, utf_constants,
                                                             net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the Individual
     certificates were loaded """

    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["privatekey.pem", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["publickey.pem", "SL_NET_PUBLIC_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["cas.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")

        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)

        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()

        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_ttls_tcp_rx_11w_c679988(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP TTLS when AP enabled WPA2 Enterprise
    with 11w capable and run TCP RX traffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="679988", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679988")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_ttls_udp_rx_11w_c679993(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP TTLS when AP enabled WPA2 Enterprise
    with 11w capable and run UDP RX tarffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="679993", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679993")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_peap_multicast_tx_11w_c679994(multicast_client, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP PEAP when AP enabled WPA2 Enterprise
    with 11w Required and run multicast TX traffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679994", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client, multicast_client=multicast_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679994")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=wifi_thread.dut_addr['dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_peap_tcp_rx_11w_c679989(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP peap when AP enabled WPA2 Enterprise
    with 11w capable and run TCP RX tarffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="679989", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679989")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_0_tcp_tx_11w_c679986(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP TLS1.0 when AP enabled WPA2 Enterprise
    with 11w capable and run TCP TX tarffic"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679986", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679986")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_2_tcp_tx_11w_c679987(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP TLS1.2 when AP enabled WPA2 Enterprise
    with 11w capable and run TCP TX tarffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679987", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679987")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_2_udp_rx_11w_c679992(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP TLS1.2 when AP enabled WPA2 Enterprise
    with 11w Required and run UDP RX traffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="679992", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679992")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_tls_1_0_udp_tx_11w_c679991(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP TLS1.0 when AP enabled WPA2 Enterprise
    with 11w Required and run UDP TXtarffic"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679991", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer,
                                                                     sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679991")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLANBLE,
        "features": Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv6Client
                          | Si91xTCPIPFeatureBitMap.IPv6Mode | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv6Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_connect_with_ipv6_c113875(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity with IPV6  using EAP TLS Method """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info(f"****** wifi_thread is initiating *******")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     protocol=protocol, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        time.sleep(10)

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        remote_ipv6 = wifi_client.interfaces.wifi.get_ip_address(version=6, addr_type="global")
        logger().info(f"remote_ipv6: {remote_ipv6}")

        ip_config = wifi_dut.interfaces.wifi.start_ip(ip_version="ipv6")
        logger().info(f"  DUT ip is ip_config: {ip_config}")
        sl_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol="TCP",
            device_ip=ip_config[1],
            host_ip=remote_ipv6,
            timeout=60,
            traffic_type="TX",
            ip_version=6,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=0)
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Default |
                    Si91xFeatureBitMap.HTTPLongerURL,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "wifi_powersave_disable", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_client_connection_wpa2_enterprise_c113805(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          wifi_client, radius_server, sl_collections, request,
                                                          http_server, http_client, index_path):
    """ This test case verifies the HTTP client connection WPA2 Enterprise """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info(f"****** wifi_thread is initiating *******")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     eap_type_tls_no_cert = False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init(https_enable=True)
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path, server_port=443)

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=443)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"

        logger().info(f"\n\n***Posting data using http post request ***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_post(
            http_server.interfaces.http,
            "cgi-bin/cgi_example.py",
            post_data='hellotestingfrohttppostcontent',
            server_port=443)

        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
        logger().info(status_dut)

        wifi_dut.interfaces.wifi.http_client_deinit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584, "priority": 8}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Default |
                    Si91xFeatureBitMap.HTTPLongerURL,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.HTTPClient,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index.html"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "wifi_powersave_disable", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_client_connection_wpa2_enterprise_c113806(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          wifi_client, radius_server, sl_collections, request,
                                                          http_server, http_client, index_path):
    """ This test case verifies the HTTP client connection WPA2 Enterprise """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info(f"****** wifi_thread is initiating *******")
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     eap_type_tls_no_cert = False)

        wifi_thread.start()
        wifi_thread.wait_for_exit()

        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
        wifi_dut.interfaces.http.http_put(http_server.interfaces.http, index_path)

        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=80)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"

        logger().info(f"\n\n***Posting data using http post request ***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_post(
            http_server.interfaces.http,
            "cgi-bin/cgi_example.py",
            post_data='hellotestingfrohttppostcontent',
            server_port=80)

        assert status_dut == SLStatus.SL_STATUS_OK, "failed to post data using http post request"
        logger().info(status_dut)

        wifi_dut.interfaces.wifi.http_client_deinit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid |
                           Si91xCustomFeatureBitMap.RealTimeClockFromHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["cacert_encrypted.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "client_cert": ["my_certification_signed", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["my_privatekey", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
    }
)
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'my_privatekey', "certificate_file": 'my_certification_signed',
                                   "ca_file": 'cacert_encrypted.pem'})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_tls_C113792(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, net_perf_client,
                                                          sniffer_filter, protocol, radius_server, sl_collections, request, wifi_client):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the encrypted certificate
        is loaded and data_traffic in it  """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        key = '"'"\\"'"'"12345678\\"'"''"'
        wifi_dut.interfaces.wifi.set_eap_credentials(credential_key=key)
        for count in range(0, utf_constants.get('iter_count')):
            wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         sl_collections=sl_collections, test_name=test_name, eap_type="tls", test_case_no="113792",
                                         data_transfer=True, wifi_client=wifi_client, traffic_type="TX", protocol=protocol, net_perf_client=net_perf_client)
            wifi_thread.start()
            wifi_thread.wait_for_exit()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = Eap_SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.radius_server("raspi_radius_server_v2")
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_fast_tls_1_0_c113778(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                      radius_server, sl_collections, request, utf_constants,
                                                      net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity in EAP FAST Method with Auto Provisioning and with TLS Version set to 1.0 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="fast", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_fast_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.radius_server("raspi_radius_server_v2")
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa2_enterprise_eap_fast_multicast_tx_11w_c679995(multicast_client, wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP FAST when AP enabled WPA2 Enterprise
    with 11w Required and run multicast TX traffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="fast", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679994", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client, multicast_client=multicast_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679994")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_fast_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=wifi_thread.dut_addr['dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.reset()
        time.sleep(15)
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.init(load_certificate=False)
        wifi_dut.interfaces.wifi.initialize_thread()
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = True


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["fast_bin.pac", "SL_NET_PACK_FILE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.radius_server("raspi_radius_server_v2")
@pytest.mark.deployed_25q2
def test_wifi_sdk_wpa2_enterprise_eap_fast_manual_provisioning_1_2_c113768(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                        sl_collections, request, utf_constants, radius_server,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP FAST Method when the certificate
        is loaded using the in tls version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="fast", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_fast_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.radius_server("raspi_radius_server_v2")
@pytest.mark.deployed_25q2
def test_wifi_sdk_wpa2_enterprise_eap_fast_auto_provisioning_1_2_c113769(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                        sl_collections, request, utf_constants, radius_server,
                                                       net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP FAST Method when the certificate
        is loaded using the in tls version 1.2 """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="fast", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(10)
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_fast_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["fast_bin.pac", "SL_NET_PACK_FILE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.radius_server("raspi_radius_server_v2")
def test_wifi_sdk_wpa2_enterprise_eap_fast_1_0_udp_tx_11w_c679990(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       sl_collections, request, utf_constants, radius_server,
                                                      net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP FAST TLS1.0 when AP enabled WPA2 Enterprise
    with 11w Required and run UDP TXtarffic"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="fast", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679990", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess_pmf_validate(wifi_sniffer=wifi_sniffer,
                                                                     sniffer_filter=sniffer_filter,
                                                                     wifi_access_point=wifi_access_point,
                                                                     dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                                     ap_bssid=ap_mac_address, test_case_no="679990", eap_type="FAST")
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_fast_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_with_websocket_ssl_c113802(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                             utf_constants, radius_server,
                                                             request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connection over ssl and data transfer functionality
    """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.websocket_init(http_server.interfaces.http, "example.com",
                                                     "/websocket",
                                                     443, 5001, enable_tls=1)
        wifi_dut.interfaces.wifi.websocket_connect()
        time.sleep(0.1)
        assert ws_handler.client_connected
        iter_count = 10
        for i in range(iter_count):
            data = text_generator(size=1362)
            address = wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
            wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)
            wifi_dut.interfaces.wifi.websocket_send(
                opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                higher_data_len=1, address=address)
            wifi_dut.interfaces.wifi.memory_free(address)
            time.sleep(2)
            logger().info(f"data received on websocket server ->{ws_handler.message_received}")
        wifi_dut.interfaces.wifi.websocket_close()
        wifi_dut.interfaces.wifi.websocket_deinit()
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_wpa2_enterprise_pmk_caching_c113790(wifi_dut, wifi_access_point, wifi_sniffer,
                                                         utf_constants, radius_server,
                                                         request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Turn OFF and Turn ON the AP.
        6. Check whether the DUT is using the PMKID for reassociation.
    """
    try:
        validation = True
        ping_count=30
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

        wifi_access_point.interfaces.wifi.enable_disable_radio(enable=False)
        time.sleep(5)
        wifi_access_point.interfaces.wifi.enable_disable_radio(enable=True)
        time.sleep(5)
        status = ping(wifi_thread.dut_addr['device_ip'], ping_count)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        logger().info("PING TO DUT IS SUCCESSFULLY DONE....")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()

        packet_filter10 = f'(wlan.fc.type_subtype==0 || eapol) && (wlan.pmkid.akms)'
        logger().info(f"Validating association, eapol from DUT for PMKID")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter10)['packet_count'], \
            'Unable to find EAP failure frames sent from AP in sniffer '

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_peap_safe1_tcp_tx_c708570(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WPA2 EAP PEAP-SAFE1 Security and run TCP TX tarffic"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peapsafe1", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
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
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa2_enterprise_eap_peap_safe2_tcp_tx_c708571(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                       radius_server, sl_collections, request, utf_constants,
                                                       net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WPA2 EAP PEAP-SAFE2 Security and run TCP TX tarffic"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_thread = WPA2Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peapsafe2", sl_collections=sl_collections, test_name=test_name)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=device_ip, remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=0, async_socket=0)
        time.sleep(5)
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_addr['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_addr['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'
        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_addr['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
