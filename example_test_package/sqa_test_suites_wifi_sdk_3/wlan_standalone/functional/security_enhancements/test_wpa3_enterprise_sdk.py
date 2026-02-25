import time
import pytest
from threading import Thread
from utf.utils.thread_base import ThreadBase
from random import randint
from example_test_package.sqa_test_suites_wifi_sdk_3.wlan_standalone.functional.cloud_connectivity.test_aws_iot_wifi_sqa_sdk import AwsConnection
from utf_wiseconnect_3.tests.devices.si91x import (Si91xCoexMode, Si91xPowerSaveModes, Si91xFeatureBitMap,
                                                   Si91xOperatingMode,
                                                   Si91xCustomFeatureBitMap,
                                                   Si91xConfigFeatureBitMap,
                                                   Si91xTCPIPFeatureBitMap,
                                                   Si91xExtCustomFeatureBitMap,
                                                   Si91xExtTCPIPFeatureBitMap,Si91xBTFeatureBitMap,
                                                   Si91xCertificateType, Si91xCertIdentifier,
                                                   Si91xPowerSaveProcedureTypes, Si91xJoinFeatureBitMap,
                                                   DeviceConstants, Si91xMqttQos, IEEE802_11W, Si91xAwsQos
                                                   )
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
import string
import random
import time
import re
from datetime import datetime
import uuid
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import get_host_ip, ping

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

    Author: CG team

"""


def text_generator(size=2000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


class SnifferValidationProcess:

    def __init__(self, wifi_sniffer=None, wifi_access_point=None, dut_mac_address=None,
                 ap_mac_address=None, conn_status=True, eap_type="tls", sniffer_filter=None, test_case_no=None):
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_mac_address = ap_mac_address
        self.conn_status = conn_status
        self.eap_type = eap_type
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no

    def verify_sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check_with_pmf_req')
        logger().info(f"Validating akms type 5 and pmf bit capable & required in sniffer")
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address, filter_name='assoc_req_resp_eapol_4_way_handshake_wpa3_eap')
        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address, filter_name='power_mgmt_bit')

        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address, ta_addr=self.dut_mac_address, filter_name='null_data_powersave')

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find akms value in beacon packet'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

    def verify_sniffer_validation_for_transition(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address, filter_name='beacon_wpa2_entr_akms_check')

        logger().info(f"Validating akms type 1 and pmf bit capable in sniffer")
        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address, filter_name='assoc_req_resp_eapol_4_wpa3_eap_trans_pmf_cap')

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address,
            da_addr=self.ap_mac_address, filter_name='power_mgmt_bit')

        packet_filter4 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_mac_address, ta_addr=self.dut_mac_address, filter_name='null_data_powersave')

        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find akms value in beacon packet'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find assoc_req_resp_eapol_4_way_handshake packet in sniffer'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

    def verify_sniffer_for_negative_scenarios(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            da_addr=self.dut_mac_address, filter_name='eap_connection_failure')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find EAP failure frames sent from AP in sniffer'

        packet_filter2 = f"(wlan.sa == {self.ap_mac_address}) && (wlan.da == ff:ff:ff:ff:ff:ff) && (wlan.fc.type_subtype == 0x0008) && (wlan.rsn.akms.type == 5)"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Checking Assoc Request for WPA3 checking rsn.akms.type 5'


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


class WPA3Enterprise(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 sl_collections=None, test_name=None, eap_type=None, eap_type_tls_no_cert=None, power_save=True,
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
        self.dut_add_dict = None
        self.device_ip = None
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.power_save = power_save
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
            if self.test_case_no == "679996" or self.test_case_no == "680012" or self.test_case_no == "680014" or self.test_case_no == "680013" or self.test_case_no == "680009":
                transfer_type = 1
                protocol = 6
                throughput_type = 1
                size = 1460

            if self.test_case_no == "679999" or self.test_case_no == "680001" or self.test_case_no == "680000":
                transfer_type = 2
                protocol = 17
                throughput_type = 4
                size = 1470

            if self.test_case_no == "679998":
                transfer_type = 2
                protocol = 17
                throughput_type = 2
                size = 1470

            if self.test_case_no == "679997":
                transfer_type = 1
                protocol = 6
                throughput_type = 3
                size = 1460

            if self.eap_type == "tls" or self.eap_type == "ttls" or self.eap_type == "peap" or self.eap_type == "fast" \
                    or self.eap_type == "peapsafe1" or self.eap_type == "peapsafe2":
                self.wifi_dut.interfaces.wifi.join(ssid=self.wifi_access_point.interfaces.wifi.ssid,
                                              passphrase=self.wifi_access_point.interfaces.wifi.passphrase,
                                              security="wpa3_enterprise", uid="user1", enc=self.eap_type)
                self.wifi_dut.interfaces.wifi.start_ip()

            self.dut_add_dict = {'dut_mac_address': self.wifi_dut.interfaces.wifi.get_mac_address(),
                                 'device_ip': self.wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)}
            logger().info(f"DUT MAC ADDRESS :  {self.dut_add_dict['dut_mac_address']}")
            logger().info(f"DUT ip: {self.dut_add_dict['device_ip']}")
            status = self.sl_collections.ping(device_ip=self.dut_add_dict['device_ip'], ping_count=10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

            if self.power_save:
                logger().info("Enabling power save Enhanced psp")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode="power_save_low_latency")
                time.sleep(10)

                # # Enables the bt power save in DUT
                logger().info("Setting DUT in bt power save...")
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                                   psp_type=Si91xPowerSaveProcedureTypes.FastPowerSave)
                time.sleep(20)

                logger().info("....Pinging DUT after power-save....")
                status = self.sl_collections.ping(device_ip=self.dut_add_dict['device_ip'], ping_count=10)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
                time.sleep(10)

            if self.data_transfer:
                logger().info(f"*** data transfer started ***")
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                if self.traffic_type == "TX":
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                         device_ip=self.dut_add_dict['device_ip'],
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info("sending data from DUT")
                    timeout = 40
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_add_dict['device_ip'], remote_ip=host_ip,
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
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_add_dict['device_ip'],
                                                                             protocol=self.protocol, bandwidth=bandwidth)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()
                        timeout = 40
                        self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                            local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            local_ip=self.dut_add_dict['device_ip'], remote_ip=host_ip,
                                                            remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                            size=size, ttl=30, throughput_type=throughput_type,
                                                            async_socket=1, timeout=timeout + 2)
                        logger().info("data received is successful")
                        time.sleep(3)

                    elif self.protocol == "TCP":
                        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip,
                                                                             device_ip=self.dut_add_dict['device_ip'],
                                                                             protocol=self.protocol)

                    def start_client():
                        time.sleep(1)
                        logger().info(f"***** start listening  ******")
                        self.net_perf_client.interfaces.net_perf.start()

                    client_thread1 = Thread(target=start_client, args=(), )
                    client_thread1.start()

                    # open socket and listen for data
                    timeout = 100
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                        local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        local_ip=self.dut_add_dict['device_ip'], remote_ip=host_ip,
                                                        remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                        size=size, ttl=30, throughput_type=throughput_type, qos=0,
                                                        async_socket=1, timeout=timeout + 2)
                    client_thread1.join()
                    logger().info("data received is successful")
                    time.sleep(3)
            if self.test_case_no == "680001" or self.test_case_no == "680000":
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
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
                                                    async_socket=1, timeout=300)

                # decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
                # wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)
                self.wifi_dut.interfaces.wifi.sl_net_leave_multicast_address()
                self.net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                time.sleep(5)

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
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_enterprise_eap_peap_udp_rx_c679999(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          radius_server, sl_collections, request,
                                                          net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WPA3 EAP PEAP Security and run UDP RX tarffic"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="peap", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="679999", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_enterprise_eap_ttls_udp_tx_c679998(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          radius_server, sl_collections, request,
                                                          net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 EAP TTLS Security and run UDP TX tarffic"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679998", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
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
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "wifi_powersave_disable", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_http_get_with_wpa3_eap_security_c680018(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          wifi_client, radius_server, sl_collections, request,
                                                          http_server, http_client):
    """
    HTTP get with wpa3 security
    """
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        index_path = "index.html"
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680018", wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init(https_enable=False)
        logger().info("\n\n***Fetching the data on http using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=80)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the http data"
        assert status_client, "failed to load the http data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"
        wifi_dut.interfaces.wifi.http_client_deinit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=
                                                                                        wifi_thread.dut_add_dict[
                                                                                            'dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wifi_sdk_https_get_with_wpa3_eap_security_c680019(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                           wifi_client, radius_server, sl_collections, request,
                                                           http_server, http_client):
    """
    HTTP get with wpa3 security
    """
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        index_path = "index.html"
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="ttls", sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680019", wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        wifi_dut.interfaces.wifi.http_client_init(https_enable=True)
        logger().info("\n\n***Fetching the data on https using get method***\n\n")
        status_dut, content_dut = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path,
                                                                    server_port=443)
        status_client, content_client = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

        assert not status_dut, "failed to fetch the https data"
        assert status_client, "failed to load the https data"

        logger().info(status_dut)
        logger().info(content_dut)
        assert content_dut == content_client, "fetched data is not same as expected data"
        wifi_dut.interfaces.wifi.http_client_deinit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_ttls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=
                                                                                        wifi_thread.dut_add_dict[
                                                                                            'dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
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
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_enterprise_eap_tls_1_0_tcp_tx_c679996(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request,
                                                             net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WAP3 EAP TLS1.0 Security and run TCP TX tarffic"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679996", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_0')
        logger().info(f"Validating EAP frames TLS version 1.0 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.0 sent'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_enterprise_eap_tls_1_2_tcp_rx_c679997(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request,
                                                             net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WAP3 EAP TLS1.2 Security and run TCP RX tarffic"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="679997", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["sha384.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server", radius_server={"private_key_file": 'sha384.pem', "certificate_file": 'sha384.pem',
                                                    "ca_file": 'sha384.pem'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wsdk_WPA3_EAP_Conn_TLS_conn_with_sha384_C680012(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         wifi_client, radius_server, sl_collections, request,
                                                         net_perf_client, protocol):
    """ This test case Verifies WPA3 Enterprise Connection with SHA384 Type Certificate"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="680012", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["cert512.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'cert512.pem', "certificate_file": 'cert512.pem',
                                   "ca_file": 'cert512.pem'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wsdk_WPA3_EAP_Conn_TLS_conn_with_sha512_C680014(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         wifi_client, radius_server, sl_collections, request,
                                                         net_perf_client, protocol):
    """ This test case Verifies WPA3 Enterprise Connection with SHA512 Type Certificate"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="680014", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
            da_addr=ap_mac_address,
            filter_name='eap_tls_cert_verification_1_2')
        logger().info(f"Validating EAP frames TLS version 1.2 in sniffer")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)['packet_count'], \
            'Unable to find EAP frames with TLS version 1.2 sent'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.legacy_deployed
def test_wsdk_WPA3_EAP_Conn_TLS_conn_with_wrong_security_C680017(wifi_dut, wifi_access_point, wifi_sniffer,
                                                         wifi_client, radius_server, sl_collections, request):
    """ This test case Verifies WPA3 Enterprise Connection with wrong security"""
    try:
        logger().info(f"Enable WPA2-ENT in 3rd party Asus Ap,"
                      f"WPA3 Enterprise on dut side")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_enterprise", uid="user1", enc="tls",
                                      expected_status=SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE)

        time.sleep(2)
        wifi_dut.interfaces.wifi.start_ip(
            expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
        logger().info(
            f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
            f" is expected")

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
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SNTPClient,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.deployed_25q2
def test_wsdk_WPA3_EAP_Conn_TLS_conn_with_sntp_C680020(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         wifi_client, radius_server, sl_collections, request,
                                                         utf_constants):
    """ This test case Verifies WPA3 Enterprise Connection with sntp connection"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680020", wifi_client=wifi_client)

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

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()

        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.end_state("wifi_dut", wifi=["load_default_fw"])
@pytest.mark.http_server("raspi_lighttpd_tls")
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
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPClient | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
                              | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.ConfigHttpOTAF,
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_https_otaf_wpa3_enterprise_c680021(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                     sniffer_filter, radius_server, sl_collections, request,
                                                     http_server):
    """ This test case verifies the https otaf in wpa3 enterprise"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        fw_version_before_upgrade = wifi_dut.interfaces.wifi.version()
        logger().info(f"*** dut fw version before upgrade = {fw_version_before_upgrade} ***")

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680021", wifi_client=wifi_client, power_save=False)
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
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
            da_addr=ap_mac_address, filter_name='assoc_req_resp_eapol_4_way_handshake_wpa3_eap')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Checking Assoc Request for WPA3 checking rsn.akms.type 5'
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
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
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Default |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Default |
                          Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W |
                               Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(
            1),
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "set_send_feature_frame": True,
        "ca_cert": ["start_field.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
        "client_cert": ["client-certificate.crt", "SL_NET_CERTIFICATE", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "client_key": ["private-key.key", "SL_NET_PRIVATE_KEY", "SL_NET_TLS_CLIENT_CREDENTIAL_START"],
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_aws_mqtt_connect_with_wpa3_eap_C686554(radius_server, wifi_sniffer, wifi_access_point, wifi_dut,
                                                    wifi_client, request, sniffer_filter, sl_collections,
                                                    aws_iot_client, utf_constants):
    """
    AWS MQTT connection with wpa3 eap security.
    """
    client_id = 'client_c686554'
    topic = "topic_c686554"
    iterations = utf_constants.get('iter_count')
    try:
        logger().info(
            f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
            f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        for iter_count in range(iterations):
            logger().info(f"Initiating aws test for iteration:{iter_count + 1}")
            messages = []
            for i in range(10):
                messages.append(text_generator(size=10))
            logger().info(f"Messages are:{messages}")

            test_name = request.node.name
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

            wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
            wifi_access_point.interfaces.wifi.start_ap()
            wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
            wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                     beacon_missed_count=40, first_time_retry_enable=0)

            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.set_eap_credentials()

            wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                         eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                         test_case_no="686554", power_save=False, wifi_client=wifi_client)
            wifi_thread.start()
            wifi_thread.wait_for_exit()

            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")

            aws_obj = AwsConnection()
            logger().info("Initiating aws connect from DUT")
            assert aws_obj.connect_to_aws_server_from_dut(wifi_dut, client_id), "Failed to connect aws server from DUT"
            logger().info("Connecting to AWS server from DUT is successful")
            aws_obj.subscribe_from_dut(wifi_dut, topic, qos=Si91xAwsQos.QOS0)
            aws_obj.connect_to_aws_server_from_raspi(aws_iot_client)
            aws_obj.subscribe_from_raspi(aws_iot_client, topic, qos=Si91xAwsQos.QOS0)

            for count, msg in enumerate(messages):
                logger().info(f"\nDUT is publishing message{count + 1} on topic:'{topic}' \nQOS:'{Si91xAwsQos.QOS0}'"
                            f"\nMessage{count + 1} with length:'{len(msg)} bytes'\nMessage{count + 1} is:'{msg}'")
                aws_obj.publish_from_dut(wifi_dut, topic, msg, qos=Si91xAwsQos.QOS0)
                time.sleep(3)
            aws_obj.validate_aws_messages_from_raspi(aws_iot_client, topic, Si91xAwsQos.QOS0, messages)

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, wifi_thread.dut_add_dict['dut_mac_address'], ap_mac_address,
                                                   sniffer_filter, power_save=False)
            packet_filter1 = f"(wlan.sa == {ap_mac_address}) && (wlan.da == ff:ff:ff:ff:ff:ff) && (wlan.fc.type_subtype == 0x0008) && (wlan.rsn.akms.type == 5)"
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
                'packet_count'], 'Checking Assoc Request for WPA3 checking rsn.akms.type 5'
            logger().info(f"Iteration '{iter_count + 1}' completed")
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
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
@pytest.mark.deployed_25q4
def test_wifi_sdk_mqtt_wpa3_transition_enterprise_c680004(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server,
                                               sl_collections, request, mqtt_server, mqtt_client, wifi_client):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 Transition
    EAP PEAP Security and run MQTT connection with data traffic """
    try:
        test_name = request.node.name
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        qos = Si91xMqttQos.QOS1
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="peap")
        wifi_dut.interfaces.wifi.start_ip()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680004", wifi_client=wifi_client)
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
        wifi_dut.interfaces.wifi.mqtt_client_disconnect(timeout=30)
        time.sleep(5)
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address, test_case_no="680004")
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_peap_verification')
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
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
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
@pytest.mark.deployed_25q2
def test_wifi_sdk_ssl_tx_socket_connection_in_wpa3_transition_enterprise_c680002(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter, radius_server, sl_collections,
                                                                   request, ssl_server, wifi_client):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 Transition EAP TLS1.2 Security and SSL TX tarffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="tls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680002", wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        socket_port = port1
        local_port = randint(5001, 20000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_add_dict['device_ip'], server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        sw = Stopwatch()
        while sw.elapsed_sec < 240:
            buffer_length = 100
            pkt_count = 1
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            ssl_server.interfaces.ssl.send_data(1, pkt_count, buffer_length, message=tx_buffer)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=70, async_timeout=70)
            assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address, test_case_no="680002")
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
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
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.SSL,
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
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.deployed_25q4
def test_wifi_sdk_ssl_rx_socket_connection_in_wpa3_transition_enterprise_c680003(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                   sniffer_filter, radius_server, sl_collections,
                                                                   request, ssl_server, wifi_client):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 Transition EAP TTLS Security and SSL TX tarffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="ttls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680003", wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1)
        server_ip = ssl_server.interfaces.ssl.server_ip
        sock = wifi_dut.interfaces.wifi.socket()
        logger().info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        socket_port = port1
        local_port = randint(5001, 20000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_thread.dut_add_dict['device_ip'], server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=socket_port)
        sw = Stopwatch()
        while sw.elapsed_sec < 60:
            buffer_length = 100
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            logger().info(f"DUT is sending data over socket {sock} and data:{tx_buffer}")
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=tx_buffer)
            time.sleep(1)
            data_receive = ssl_server.interfaces.ssl.data_recv_content(1, buffer_size=len(tx_buffer))
            logger().info(f"Data received on remote SSL socket is -> {data_receive.decode()}")
            assert tx_buffer == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on remote peer is matching")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_ttls_verification')
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
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
                       wifi=["multicast_leave", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.deployed_25q4
def test_wifi_sdk_wpa3_transition_enterprise_eap_tls_multicast_rx_c680001(multicast_client, wifi_dut, wifi_access_point,
                                                                           wifi_sniffer, sniffer_filter, radius_server,
                                                                           sl_collections, request, net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with EAP tls 1.0 when AP enabled WPA3 transition Enterprise
    and run multicast RX traffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="tls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="680001", net_perf_client=net_perf_client,
                                     protocol=protocol, wifi_client=wifi_client, multicast_client=multicast_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
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
        "band": 0,
        "eap_cert": ["sha384.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server", radius_server={"private_key_file": 'sha384.pem', "certificate_file": 'sha384.pem',
                                                    "ca_file": 'sha384.pem'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.deployed_25q4
def test_wsdk_WPA3_EAP_transition_Conn_TLS_conn_with_sha384_C680013(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         wifi_client, radius_server, sl_collections, request,
                                                         net_perf_client, protocol):
    """ This test case Verifies WPA3 Enterprise transition Connection with SHA384 Type Certificate"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="tls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679996", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["cert512.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server", radius_server={"private_key_file": 'cert512.pem', "certificate_file": 'cert512.pem',
                                                    "ca_file": 'cert512.pem'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.deployed_25q4
def test_wsdk_WPA3_EAP_transition_Conn_TLS_conn_with_sha512_C680015(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                         wifi_client, radius_server, sl_collections, request,
                                                         net_perf_client, protocol):
    """ This test case Verifies WPA3 Enterprise transition Connection with SHA512Type Certificate"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="tls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="679996", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
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
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user-header.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server", radius_server={"private_key_file": 'wifi-user.pem', "certificate_file": 'wifi-user.pem',
                                                    "ca_file": 'wifi-user.pem'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.deployed_25q4
def test_wifi_sdk_wpa_3enterprise_eap_tls_C680024(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants,
                                                  sniffer_filter, radius_server, sl_collections, request):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the certificate
            header is removed from certificate """
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired |
                                Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.set_eap_credentials()
        iter_count =  utf_constants.get('iter_count')
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa3_enterprise", uid="user1", enc="tls",
                                          expected_status=(SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION | SLStatus.SL_STATUS_SI91X_DEAUTH_REQUEST_FROM_SUPPLICANT))
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
            assert (result == '4D' or result == '53'), "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code {result}, which means PEM Header error and hence test cases is passed. Hence, Test Case PASSED")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address)
            sniffer_verification.verify_sniffer_for_negative_scenarios()

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
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
@pytest.mark.legacy_deployed
def test_wifi_sdk_wpa3_enterprise_eap_ttls_wrong_user_identity_C680022(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                       utf_constants,
                                                                       sniffer_filter, radius_server, sl_collections,
                                                                       request):
    """ This test case verifies the WPA3 Enterprise Connectivity while using EAP TTLS Method when wrong
            user identity"""
    try:
        test_name = request.node.name
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"****** DUT MAC ADDRESS **** {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"**** AP mac address*****{ap_mac_address}")
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.set_eap_credentials(username='user2', password='12345678')

        for count in range(0, utf_constants.get('iter_count')):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa3_enterprise", uid="user1", enc="ttls",
                                          expected_status=SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION)
            wifi_dut.interfaces.wifi.start_ip(
                expected_status=SLStatus.SL_STATUS_SI91X_COMMAND_GIVEN_IN_INVALID_STATE)
            logger().info(
                f"IP configuration failed when command given in incorrect state,observed error code 0x10021 which "
                f" is expected")
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
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
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs", "reset_wifi_conn_stats"])
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.legacy_deployed
def test_wsdk_WPA3_EAP_TLS_with_no_client_certs_C680023(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                        wifi_client, radius_server, sl_collections, request,
                                                        utf_constants):
    """ This test case Verifies the wpa3 enterprise connectivity with no tls client certs in certs"""
    output = None
    try:
        test_name = request.node.name
        iter_count = utf_constants.get("iter_count")
        wifi_dut.interfaces.wifi.clear_certificate(cert_type=Si91xCertificateType.SL_NET_CERTIFICATE,
                                                   cert_identifier=Si91xCertIdentifier.SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID)
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["privatekey.pem", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["cas.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.set_eap_credentials()
        for i in range(0, iter_count):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

            wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
            wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                          passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                          security="wpa3_enterprise", uid="user1", enc="tls",
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
            assert result == '2A', "Unable to get expected reason code hence test is failed"
            logger().info(f"Observed Expected Error Code, Hence test cases is passed")
            ap_mac_address = wifi_access_point.interfaces.wifi.bssid
            logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
            dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
            logger().info(f"Mac Address of DUT: {dut_mac_address}")
            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()
            sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                            wifi_access_point=wifi_access_point,
                                                            dut_mac_address=dut_mac_address,
                                                            ap_mac_address=ap_mac_address, test_case_no=None)
            sniffer_verification.verify_sniffer_for_negative_scenarios()
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
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.DNSClient
        | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.RsaKeyWith4096Support
                               | Si91xExtCustomFeatureBitMap.SslCertWith4096Support |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V2 | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
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
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "clear_certs"])
@pytest.mark.deployed_25q2
def test_wsdk_WPA3_EAP_AWS_shadow_connection_C686555(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                     wifi_client, radius_server,
                                                     sl_collections, request):
    """ This test case Verifies AWS Shadow connection with WPA3 Enterprise security"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="686555", wifi_client=wifi_client, eap_type="tls", power_save=True)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        client_id = "_client"
        topic = "topic_"
        logger().info(f"The client_id is {client_id} and topic is {topic}")
        wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
        wifi_dut.interfaces.wifi.aws_iot_shadow_init(
            hostname="a2m21kovu9tcsh-ats.iot.ap-southeast-1.amazonaws.com"
        )
        logger().info(f"\n ....Initiating Connection to AWS Cloud.... \n")
        wifi_dut.interfaces.wifi.aws_iot_shadow_connect(timeout=120)
        wifi_dut.interfaces.wifi.aws_iot_shadow_register_delta()
        logger().info(f"\n\n Getting Shadow Update for 3 min(180 sec)\n\n ")
        start_time = time.time()
        while time.time() - start_time < 180:
            wifi_dut.interfaces.wifi.aws_iot_shadow_yield()
            wifi_dut.interfaces.wifi.aws_iot_shadow_init_json_document()
            wifi_dut.interfaces.wifi.aws_iot_shadow_add_reported()
            wifi_dut.interfaces.wifi.aws_iot_finalize_json_document()
            wifi_dut.interfaces.wifi.aws_iot_shadow_update()

        logger().info(f"\n....Disconnecting from AWS Cloud....\n")
        wifi_dut.interfaces.wifi.aws_iot_mqtt_disconnect()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point, eap_type="tls",
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_tls_verification')
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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.deployed_25q2
def test_wifi_sdk_mqtt_wpa3_transition_EAP_FAST_security_c680005(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, radius_server,
                                               sl_collections, request, mqtt_server, mqtt_client, wifi_client):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 Transition
    EAP FAST Security and run MQTT connection with data traffic """
    try:
        test_name = request.node.name
        topic = "mytesttopic"
        message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=300))
        qos = Si91xMqttQos.QOS1
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="fast")
        wifi_dut.interfaces.wifi.start_ip()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     test_case_no="680004", wifi_client=wifi_client)
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
        wifi_dut.interfaces.wifi.mqtt_client_disconnect(timeout=30)
        time.sleep(5)
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address, test_case_no="680004")
        sniffer_verification.verify_sniffer_validation_for_transition()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_fast_verification')
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
        "thread_config": {"wifi": {"count": 1, "stack_len": 4096}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity |
                    Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["cacert_encrypted.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["my_certification_signed.key", "SL_NET_PUBLIC_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "client_key": ["my_privatekey.key", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'my_privatekey.key', "certificate_file": 'my_certification_signed.key',
                                   "ca_file": 'cacert_encrypted.pem', "private_key_password": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
def test_wifi_sdk_wpa3_enterprise_with_encrypt_cert_c680025(wifi_dut, radius_server, wifi_access_point, wifi_sniffer, sniffer_filter,
                                               sl_collections, request, wifi_client):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 enterprise connection
    when wrong private_key_password is given """
    try:
        test_name = request.node.name

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0)
        wifi_dut.interfaces.wifi.set_eap_credentials(username='user1', password='12345678',
                                                     credential_key='"'"\\"'"'"123456789\\"'"''"')
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_enterprise", uid="user1", enc="tls",
                                      expected_status=(SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION | SLStatus.SL_STATUS_SI91X_DEAUTH_REQUEST_FROM_SUPPLICANT))
        time.sleep(2)
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
        assert result == '46', "Unable to get expected reason code hence test is failed"
        logger().info(f"Observed Expected Error Code, Hence test cases is passed")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Mac Address of DUT: {dut_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address,
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_for_negative_scenarios()

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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["cacert_encrypted.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["my_certification_signed.key", "SL_NET_PUBLIC_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "client_key": ["my_privatekey.key", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'my_privatekey.key', "certificate_file": 'my_certification_signed.key',
                                   "ca_file": 'cacert_encrypted.pem', "private_key_password": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa3_eap_security_with_encrypt_cert_c680010(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                            sl_collections, request, radius_server,
                                                            net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to connect or not when DUT connects to AP with WPA3 EAP security with encrypted certificates are used"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0)
        wifi_dut.interfaces.wifi.set_eap_credentials(credential_key='"'"\\"'"'"12345678\\"'"''"')
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     eap_type="tls", sl_collections=sl_collections, test_name=test_name,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        time.sleep(3)

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
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
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='assoc_req_resp_eapol_4_way_handshake_wpa3_eap')
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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.UartSelForDebugPrints |
                               Si91xExtCustomFeatureBitMap.Default |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["cacert_encrypted.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "ca_cert": ["my_certification_signed.key", "SL_NET_PUBLIC_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
        "client_key": ["my_privatekey.key", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={"private_key_file": 'my_privatekey.key', "certificate_file": 'my_certification_signed.key',
                                   "ca_file": 'cacert_encrypted.pem', "private_key_password": '12345678'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_wpa3_transition_enterprise_with_encrypt_cert_c680011(wifi_dut, radius_server, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                                       sl_collections, request,
                                                                       net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with WAP3 Transition
    EAP TLS with data traffic """
    try:
        test_name = request.node.name

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0)
        wifi_dut.interfaces.wifi.set_eap_credentials(credential_key='"'"\\"'"'"12345678\\"'"''"')

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="tls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name, power_save=True,
                                     wifi_client=wifi_client)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
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
        logger().info("Disconnecting from DUT")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=dut_mac_address,
                                                        ap_mac_address=ap_mac_address, test_case_no="680011")
        sniffer_verification.verify_sniffer_validation_for_transition()

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
                           | Si91xConfigFeatureBitMap.TLS_V1,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["fast_bin.pac", "SL_NET_PACK_FILE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["multicast_leave", "unassociated", "wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.radius_server("raspi_radius_server_v2")
@pytest.mark.deployed_25q2
def test_wifi_sdk_wpa3_enterprise_eap_fast_multicast_rx_c680000(multicast_client, wifi_dut, wifi_access_point,
                                                                           wifi_sniffer, sniffer_filter, radius_server,
                                                                           sl_collections, request, net_perf_client, wifi_client, protocol):
    """ Verify whether DUT is able to scan and connect to AP with WPA3 EAP fast tls 1.0 security and run multicast RX traffic """
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="RX", test_case_no="680000", net_perf_client=net_perf_client,
                                     protocol=protocol, wifi_client=wifi_client, multicast_client=multicast_client, eap_type="fast")
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_dut.interfaces.wifi.leave()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_fast_verification')
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
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.deployed_25q4
def test_wifi_sdk_wpa3_enterprise_eap_peap_safe1_tcp_tx_c708572(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          radius_server, sl_collections, request,
                                                          net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WPA3 EAP PEAP-SAFE1 Security and run UDP RX tarffic"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
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
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

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
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.deployed_25q4
def test_wifi_sdk_wpa3_enterprise_eap_peap_safe2_tcp_tx_c708573(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                          radius_server, sl_collections, request,
                                                          net_perf_client, wifi_client, protocol):
    """Verify whether DUT is able to scan and connect to AP with WPA3 EAP PEAP-SAFE2 Security and run UDP RX tarffic"""
    try:
        logger().info(f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
                      f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
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
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=wifi_thread.dut_add_dict['dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.RsaKeyWith4096Support |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user_4096.pem", "SL_NET_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"],
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
def test_wifi_sdk_wpa3_enterprise_eap_with_4k_length_c680008(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request, utf_constants,
                                                             net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA3 Enterprise Connectivity while using EAP TLS Method when the 4096 Length
        certificates were loaded """
    try:
        logger().info(
            f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
            f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Required'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
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
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=
                                                                                        wifi_thread.dut_add_dict[
                                                                                            'dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.RsaKeyWith4096Support |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
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
def test_wifi_sdk_wpa3_enterprise_transition_eap_with_4k_individual_length_c680009(wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter,
                                                             radius_server, sl_collections, request, utf_constants,
                                                             net_perf_client, wifi_client, protocol):
    """ This test case verifies the WPA2 Enterprise Connectivity while using EAP TLS Method when the 4096 Length
        certificates were loaded """
    try:
        logger().info(
            f"Since WPA3-ENT is not supported in 3rd party Asus Ap , as per input from QA team configured "
            f"wpa2-ent-pmf on 3rd party side and on dut enabled wpa3-enterprise with pmf")
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        wifi_access_point.interfaces.wifi.config['protected_management_frame'] = 'Capable'
        wifi_access_point.interfaces.wifi.start_ap()
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)


        wifi_dut.interfaces.wifi.load_certs(
            eap_cert=["cas_4096.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            ca_cert=["publickey_4096.pem", "SL_NET_PUBLIC_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.load_certs(
            client_key=["privatekey_4096.pem", "SL_NET_PRIVATE_KEY", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"])
        wifi_dut.interfaces.wifi.scan(channel=0, ssid=wifi_access_point.interfaces.wifi.ssid)
        wifi_dut.interfaces.wifi.set_eap_credentials()

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
        wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid,
                                      passphrase=wifi_access_point.interfaces.wifi.passphrase,
                                      security="wpa3_transition_enterprise", uid="user1", enc="tls")
        wifi_dut.interfaces.wifi.start_ip()
        wifi_thread = WPA3Enterprise(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     sl_collections=sl_collections, test_name=test_name,
                                     traffic_type="TX", test_case_no="680009", net_perf_client=net_perf_client,
                                     protocol=protocol, data_transfer=True, wifi_client=wifi_client)
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
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_verification = SnifferValidationProcess(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                        wifi_access_point=wifi_access_point,
                                                        dut_mac_address=wifi_thread.dut_add_dict['dut_mac_address'],
                                                        ap_mac_address=ap_mac_address)
        sniffer_verification.verify_sniffer_validation()
        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            da_addr=ap_mac_address,
            sa_addr=wifi_thread.dut_add_dict['dut_mac_address'], filter_name='eap_type_peap_verification')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer'

        logger().info("validate NULL data frame with PM bit set to '1'")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(da_addr=ap_mac_address,
                                                                                        sa_addr=
                                                                                        wifi_thread.dut_add_dict[
                                                                                            'dut_mac_address'],
                                                                                        filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find power management bit in QOS null frames in sniffer capture'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()