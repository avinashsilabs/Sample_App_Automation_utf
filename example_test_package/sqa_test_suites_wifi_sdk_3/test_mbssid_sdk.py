import re
import time
from retry import retry
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xJoinFeatureBitMap,
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from test_wlan_data_rates_sdk import SocketDataTransfer
from collections import Counter
from utf.interfaces.iperf.iperf_constants import IperfConstants


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Validate MBSSID support in Third party AP's
        4. Scan available ssid's in vicinity and compare with AP configured VAP's list
        5. Connect DUT with T & NT based ssid with different security modes. 
        6. Trigger TCP/UDP traffic suing socket/iperf API's.
        7. Enable rejoin and verify the same functionality with different security modes.
        8. Verify in concurrent modes.

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vivek Verma
"""


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, sniffer_filter=None
                 , ping_count=None, test_name=None, sl_collections=None, t_profile_bssid=None, net_perf_client=None,
                 wifi_client=None, switch=None, wifi_clients=None, protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.t_profile_bssid = t_profile_bssid
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.protocol = 'tcp'
        self.data = 'Thisisfromclient'
        self.time_period = 60
        self.switch = switch
        self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
        self.ssid = "SILABS_AP_MODE"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.channel = "3"
        self.dtim_count = "1"
        self.beacon_interval = "100"
        self.no_of_clients = 1
        self.protocol=protocol

    def run(self):
        try:
            logger().info("\n\n *** Start Sniffer finally **** \n\n ")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)

            if self.test_case_no == 219285:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()

            if self.test_case_no == 219286:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False)

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            if self.test_case_no == 219288:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True)

                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            if self.test_case_no == 219289:
                self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.
                        MgmtFrameProtectionRequired)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.
                                                                         associated,
                                                                         power_save=True, ping_after_power_save=True)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            if self.test_case_no == 219290:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                    join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.
                        MgmtFrameProtectionRequired)
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid=vap_list[0],
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True)

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            elif self.test_case_no == 219291:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type='tls',
                                                                        ping_after_power_save=True, retry_count=3)

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            elif self.test_case_no == 219292:
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        ssid=vap_list[0],
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type='tls',
                                                                        ping_after_power_save=True, retry_count=3)

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            elif self.test_case_no == 219293:
                """ Enabling Rejoin """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()

                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.
                                                                         associated,
                                                                         power_save=True, ping_after_power_save=True)
                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                     dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            elif self.test_case_no == 219295:
                """ Enabling Rejoin """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
                vap_list = self.verfiy_T_and_NT_based_mbssid_in_dut_list()
                self.wifi_dut.interfaces.wifi.scan()
                self.wifi_dut.interfaces.wifi.join(ssid='vivek_2g',
                                                   security=self.wifi_access_point.interfaces.wifi.security.name.lower(),
                                                   passphrase=self.wifi_access_point.interfaces.wifi.passphrase)
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=False
                                                                         , ping_after_power_save=False, skip_scan=True,
                                                                         skip_connect=True)

                logger().info("DUT successfully connected with AP")
                time.sleep(2)
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

                socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data,
                                                dut_ip=self.dut_addr['device_ip'])

                socket_obj.socket_data_transfer()

            elif self.test_case_no == 219307:
                self.traffic_type="Tx"
                logger().info("********** configuring the sniffer with access point channel **********")
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.channel)
                logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file='test_mbssid_concurrent_mode')
                time.sleep(3)
                ping_count = 10
                self.ipconfig1 = self.sl_collections.configure_dut_in_static_ip(self.wifi_dut,
                                                                                static_ip="192.168.100.76",
                                                                                static_subnet="255.255.255.0",
                                                                                static_gateway="192.168.100.76")

                self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                                    channel=self.channel,
                                                                                    ssid=self.ssid,
                                                                                    security=self.security,
                                                                                    password=self.password,
                                                                                    dtim_count=self.dtim_count,
                                                                                    beacon_interval=self.beacon_interval,
                                                                                    ping_count=ping_count,
                                                                                    no_of_clients=self.no_of_clients,
                                                                                    leave=False
                                                                                    )
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         power_save=False,
                                                                         ping_after_power_save=True, retry_count=3,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         )

                self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
                logger().info(f"ap_bssid : {self.ap_mac_address}")
                if self.traffic_type == "Tx":
                    logger().info(f"***** starting iperf ******")
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr_dict['client_ip'],
                                                                         device_ip=self.dut_addr_dict['dut_ip'],
                                                                         protocol=self.protocol)
                    self.net_perf_client.interfaces.net_perf.start()
                    logger().info(f"***** send traffic  ******")
                    self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                        local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        local_ip=self.dut_addr_dict['dut_ip'],
                                                        remote_ip=self.dut_addr_dict['client_ip'],
                                                        remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                        size=1460, ttl=30, throughput_type=1, qos=0)
                    logger().info(f"***** get and print throughput ******")
                    tp = self.net_perf_client.interfaces.net_perf.process_output()
                    assert tp, "failed to get throughput..."
                    logger().info("data transfer is successful")
                logger().info("Stop sniffer finally")
                self.wifi_sniffer.interfaces.capture.stop_capture()

            else:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated
                                                                         , ping_after_power_save=False)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

    def find_mbssid_vaps(self):
        packet_filter = '                    SSID:'
        count = 0
        ssid_list = []
        final_ssid_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        logger().info(f'\n\n *** Trying to collect all T & NT based SSID from beacon packet *** \n\n')
        for x in line:
            if packet_filter in x:
                print(x)
                ssid_list.append(x)
                output = ssid_list[count].strip().split(':')[1].strip().replace('"', "")
                final_ssid_list.append(output)
                count = count + 1
        return final_ssid_list

    def find_ssid_list_from_dut_scan(self):
        ssid_list = []
        scan_list = self.wifi_dut.interfaces.wifi.scan()
        logger().info(f'\n\n *** Start to collect all available ssid in DUT scan list ***\n\n')
        for i in range(0, len(scan_list)):
            ssid_list.append(scan_list[i].ssid)
        logger().info(f'\n\n SSID LIST ={ssid_list}\n\n')
        return ssid_list

    def compare_list(self, list1, list2):
        """Returns True if list1 contains all elements of list2, False otherwise."""
        counter1 = Counter(list1)
        counter2 = Counter(list2)

        # Check if counter2 is a subset of counter1
        return all(counter2[element] <= counter1[element] for element in counter2)

    def verfiy_T_and_NT_based_mbssid_in_dut_list(self):
        packet_filter2 = '                    SSID:'
        ssid_list = self.find_ssid_list_from_dut_scan()
        time.sleep(2)
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address,
            radio_ch=self.wifi_access_point.interfaces.wifi.channel,
            filter_name='beacon_mbssid')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                       packet_filter2=packet_filter2)[
            'packet_count'], \
            'Unable to find MBSSID bit enable in extended capability field in sniffer capture'

        vap_list = self.find_mbssid_vaps()
        ''' Start verification for T & NT based scan list is available in DUT scan list '''
        assert self.compare_list(vap_list, ssid_list), 'Unable to match DUT ssid list with configured VAP list'
        logger().info("\n ***** DUT is able to scan all VAP's info *****")
        return vap_list


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_c219284(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name
    packet_filter2 = '                .1.. .... = Multiple BSSID: Supported'

    '''	Verify whether DUT is able to send probe req/Assoc req with MBSSID support when enabled MBSSID 
        feature( Multiple BSSID field of the Extended Capabilities element)'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info(f"\n\n\n DUT MAC Address = {wlan_obj.dut_addr['dut_mac_address']}\n\n")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            radio_ch=wifi_access_point.interfaces.wifi.channel,
            filter_name='assoc_mbssid')

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find MBSSID bit enable in extended capability field in sniffer capture'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_scan_all_vap_c219285(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections):
    ping_count = utf_constants.get("ping_count")
    test_name = request.node.name

    '''Verify whether DUT is able to scan all VAP's info when enabled MBSSID feature in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          sniffer_filter=sniffer_filter, ping_count=ping_count, test_name=test_name,
                          sl_collections=sl_collections, test_case_no=219285)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_open_sec_c219286(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with open security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219286,
                          sniffer_filter=sniffer_filter
                          , t_profile_bssid=t_profile_bssid, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_T_wpa2psk_c219287(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to connect to T profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219286,
                          sniffer_filter=sniffer_filter
                          , t_profile_bssid=t_profile_bssid, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_NT_wpa2_psk_c219288(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to connect to NT based profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219288,
                          sniffer_filter=sniffer_filter
                          , t_profile_bssid=t_profile_bssid, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
            CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
            SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_T_wpa3_c219289(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    test_name = request.node.name
    '''Verify whether DUT is able to connect to T profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219289,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
            CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
            SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_NT_wpa3_c219290(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    test_name = request.node.name
    '''Verify whether DUT is able to connect to NT profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219290,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

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
def test_wifi_sdk_mbssid_T_wpa2_enterprise_c219291(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    test_name = request.node.name
    '''Verify whether DUT is able to connect to T profile BSSID with WPA2 enterprise security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219291,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

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
def test_wifi_sdk_mbssid_NT_wpa2_enterprise_c219292(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client):
    test_name = request.node.name
    '''Verify whether DUT is able to connect to NT profile BSSID with WPA2 enterprise security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219292,
                          sniffer_filter=sniffer_filter, net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'Open'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_rejoin_T_open_sec_c219293(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client, switch):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to T profile BSSID with open security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219293,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("\n *** Start sniffer configuration *** \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            filter_name="beacon")

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_rejoin_T_wpa2_c219294(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client, switch):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to T profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219293,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("\n *** Start sniffer configuration *** \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            filter_name="beacon")

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Beacon packet after AP turn on'

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": 'gnbax', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_mbssid_rejoin_NT_wpa2_c219295(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client, switch):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to NT profile BSSID with WPA2 PSK security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219295,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("\n *** Start sniffer configuration *** \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            filter_name="beacon")

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Beacon packet after AP turn on'

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
            CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
            SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_rejoin_T_wpa3_c219296(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client, switch):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to T profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219289,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        logger().info("\n *** Enable Rejoin *** \n")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                      beacon_missed_count=40,
                                                                      first_time_retry_enable=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("\n *** Start sniffer configuration *** \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            filter_name="beacon")

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Beacon packet after AP turn on'

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA3'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.
            CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | Si91xExtCustomFeatureBitMap.
            SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 | Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

    }
)
def test_wifi_sdk_mbssid_rejoin_NT_wpa3_c219297(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_client, switch):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name

    '''Verify whether DUT is able to rejoin to NT profile BSSID with WPA3 Personal security enabled in AP'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219290,
                          sniffer_filter=sniffer_filter, switch=switch, t_profile_bssid=t_profile_bssid,
                          net_perf_client=net_perf_client, wifi_client=wifi_client)
    try:
        logger().info("\n *** Enable Rejoin *** \n")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                      beacon_missed_count=40,
                                                                      first_time_retry_enable=0)
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("\n *** Start sniffer configuration *** \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_bssid,
            filter_name="beacon")

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Beacon packet after AP turn on'

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "open", "ssid": "SILABS_AP_MODE", "channel": 3
    },
)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_clients",
    wifi={
           0: {
                "security": "open",
                "ssid": "SILABS_AP_MODE",
                "passphrase": "Automation@123",
                "channel": 3,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'open',
        'passphrase': 'test1234',
        'channel': 3,
    }
)
def test_wifi_sdk_mbssid_T_open_sec_concurrent_c219307(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                 sniffer_filter, sl_collections, net_perf_client, wifi_clients, protocol):
    t_profile_bssid = utf_constants.get("t_profile_bssid")
    test_name = request.node.name
    '''Connection to T profile BSSID AP(open) in Concurrent mode'''

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, sl_collections=sl_collections, test_case_no=219307,
                          sniffer_filter=sniffer_filter
                          , t_profile_bssid=t_profile_bssid, net_perf_client=net_perf_client, wifi_clients=wifi_clients, protocol=protocol)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


