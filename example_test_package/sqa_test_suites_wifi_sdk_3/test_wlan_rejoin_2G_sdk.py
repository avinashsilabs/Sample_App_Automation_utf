import re
import time
from utf.utils.time_measurer import TimeMeasurer
import pytest as pytest
from utf import UtfDatabaseProperties
from utf.utils.iperf.iperf_utils import ping
from test_wlan_data_rates_sdk import SocketDataTransfer
import threading
from threading import Thread, Event
from utf.utils.thread_base import ThreadBase
from utf.interfaces.wifi import WlanError
from utf.utils.logger import get_logger
from utf.interfaces.wifi import SecurityMode
from utf.interfaces.shell.ssh_shell import SSHShell
from utf.utils import get_tls_certificate_dir
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
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xCertificateType,
    Si91xCertIdentifier,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    SocketOptions,

)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This function runs below test steps for DUT-Si91x for Rejoin test case verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number and send data.
        7. Turn off Access point and check unicast Probe request packet in sniffer after some time it should start 
           broadcast probe request packet
        8. verify rejoin & probe request packet with different security, different channels, and for different region(US/UK/Japan) 
        9. Note: TC - 19724 is duplicate, TC-19726/27/28 current UTF implementation doesn't support.
           TC-19730/31/32 are depend on TLS/TTLS/PEAP


    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

"""
class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None,
                 ping_count=None, data_transfer=True, test_name=None, sl_collections=None, switch=None):
        super().__init__()
        self.socket_obj = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = 'Thisisfromclient'
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.switch = switch
        self.rejoin_event = None
        self.dut_addr = None
        self.socket_id = None

    def run(self):
        try:
            if self.test_case_no == 19721:
                """ Enabling Rejoin """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
            elif self.test_case_no == 19722:
                """ Enabling Rejoin for max retry count = 4 """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=4,
                                                                         scan_interval=4,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
                self.rejoin_event=True
            elif self.test_case_no == 19729:
                """ Enabling Rejoin for security mode change"""
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=4, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
            elif self.test_case_no == 19733:
                """ Enabling Rejoin for security mode change"""
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=20, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)
            elif self.test_case_no == 19735:
                """ Enabling Rejoin with retry bit enable"""
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=1)
            elif self.test_case_no == 19736:
                """ Enabling Rejoin with reset beacon missed counter"""
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=100,
                                                                         first_time_retry_enable=0)

            elif self.test_case_no == 19737:
                """Enabling Rejoin with scan interval 1 second"""
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=4, scan_interval=1,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
            elif self.test_case_no == 19739:
                """ Enabling BG scan """
                self.wifi_dut.interfaces.wifi.set_advanced_scan_configuration(adv_active_channel_time=15,
                                                                              adv_passive_channel_time=20)

                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                beacon_missed_count=40, first_time_retry_enable=0)

            elif self.test_case_no == 19740:
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=4, scan_interval=6,
                                                                         beacon_missed_count=200,
                                                                         first_time_retry_enable=1)
            elif self.test_case_no == 19741:
                """ Enabling Rejoin """
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)

            elif self.test_case_no == 19742:
                "Set region code US"
                logger().info(f"setting the DUT region to US")
                self.wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.US)
                time.sleep(5)

                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)

            elif self.test_case_no == 19743:
                "Set region code EU"
                logger().info(f"setting the DUT region to EU")
                self.wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.Europe)

                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)
            elif self.test_case_no == 19744:
                "Set region code EU"
                logger().info(f"setting the DUT region to EU")
                self.wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.Japan)

                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)

            elif self.test_case_no == 19745:
                "Set region code EU"
                logger().info(f"setting the DUT region to Worldwide")
                self.wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.Worldwide)

                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=6,
                                                                              beacon_missed_count=40,
                                                                              first_time_retry_enable=0)

            logger().info('******* Turn on Access point **********')
            self.switch.interfaces.pdu_switch.turn_on(delay=30)
            logger().info("\n *** Start sniffer configuration *** \n")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            if self.test_case_no == 19740:
                self.wifi_access_point.interfaces.wifi.passphrase = "12345679"
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point, expected_status=
                SLStatus.SL_STATUS_SI91X_DEAUTHENTICATION or SLStatus.SL_STATUS_SI91X_REJOIN_FAILURE)
            elif self.test_case_no == 19741:
                dut_add_dict = {}
                logger().info("Initiating wlan Scan from DUT")
                scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=self.wifi_access_point.interfaces.wifi.ssid)
                logger().info(scan_results)
                assert len(scan_results) > 0, "scan_list not found"
                self.wifi_dut.interfaces.wifi.join(self.wifi_access_point.interfaces.wifi.ssid)

                ip_status, ip_config = self.sl_collections.configure_ip(self.wifi_dut)
                logger().info(f"\n ***ip_status={ip_status},  ip_config={ip_config}*** \n")

                # we fetch the ip address and mac_address
                device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                logger().info(f"DUT ip: {device_ip}")
                dut_add_dict['device_ip'] = device_ip
                dut_add_dict['dut_mac_address'] = self.wifi_dut.interfaces.wifi.get_mac_address()
                logger().info(
                    f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']} DUT IP ADDRESS : {dut_add_dict['device_ip']}")

                # ping to DUT before power_save
                status = self.sl_collections.ping(device_ip=dut_add_dict['device_ip'], ping_count=10)
                assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

                logger().info(f"....Applying performance profile mode")
                self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
                self.wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                              psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

                self.dut_addr = dut_add_dict

            elif self.test_case_no == 19730:
                self.wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)

                logger().info("Setting Rejoin Parameters in DUT")
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                         scan_interval=4,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)

                logger().info("DUT Joining to AP in EAP-TLS mode")
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type="tls", ping_after_power_save=True)
                time.sleep(5)
                self.socket_data_transfer_recovery_in_rejoin(option_name=SocketOptions.SOL_SOCKET, option_val=SocketOptions.TCP_MAX_RETRY)
                wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

            elif self.test_case_no == 19731:
                self.wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)

                logger().info("Setting Rejoin Parameters in DUT")
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                         scan_interval=4,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)

                logger().info("DUT Joining to AP in EAP-TTLS mode")
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type="ttls", ping_after_power_save=True)
                time.sleep(5)
                self.socket_data_transfer_recovery_in_rejoin(option_name=SocketOptions.SOL_SOCKET, option_val=SocketOptions.TCP_MAX_RETRY)
                wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

            elif self.test_case_no == 19732:
                self.wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=60, trigger_level_change=4)

                logger().info("Setting Rejoin Parameters in DUT")
                self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0,
                                                                         scan_interval=4,
                                                                         beacon_missed_count=40,
                                                                         first_time_retry_enable=0)

                logger().info("DUT Joining to AP in EAP-PEAP mode")
                self.dut_addr = self.sl_collections.join_to_eap_network(wifi_dut=self.wifi_dut,
                                                                        wifi_access_point=self.wifi_access_point,
                                                                        eap_type="peap", ping_after_power_save=True)
                time.sleep(5)
                self.socket_data_transfer_recovery_in_rejoin(option_name=SocketOptions.SOL_SOCKET, option_val=SocketOptions.TCP_MAX_RETRY)
                wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

            else:
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated
                                                                     , ping_after_power_save=False,
                                                                     channel=self.wifi_access_point.interfaces.wifi.channel)
                logger().info("DUT successfully connected with AP")
            time.sleep(2)

            if self.test_case_no == 19739:
                logger().info("\n *** Enable BGscan *** \n")
                self.wifi_dut.interfaces.wifi.scan(bgscan=True, bg_scan_periodicity=10)

            if self.data_transfer:
                self.socket_obj = SocketDataTransfer(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point,
                                                     time_period=self.time_period, data=self.data, dut_ip=self.dut_addr['device_ip'])
                self.socket_obj.socket_data_transfer()

            if self.rejoin_event:
                logger().info("Stop sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(2)
                self.wifi_sniffer.interfaces.capture.configure_interface(
                    channel=self.wifi_access_point.interfaces.wifi.channel)
                self.wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_event_start")
                self.switch.interfaces.pdu_switch.turn_off()

                assert self.rejoin_async_event(), "Did not receive an expected rejoin error event"

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

    def socket_data_transfer_recovery_in_rejoin(self, option_name=None, option_val=None, bsdSetSocketOpt=True,
                                                option_length=None, timeout=10):
        end_time = 300

        """ This method is responsible to validate socket data transfer recovery after rejoin event """

        if isinstance(self.wifi_dut.interfaces.wifi, SLWifiCLI):
            self.socket_id = self.wifi_dut.interfaces.wifi.socket(timeout=15)
            if isinstance(self.socket_id, int):
                logger().info(f"Socket open successfully : {self.socket_id}")
            else:
                logger().error(f"Unable to open socket id: {self.socket_id}")
                raise RuntimeError(self.socket_id)

            logger().error(f"\n\n Socket bind in DUT for socket-id: {self.socket_id}")
            self.wifi_dut.interfaces.wifi.bind(socket_fd=self.socket_id, device_ip=self.dut_addr['device_ip'], timeout=15)
            logger().error(f"\n\n Trying to connect with server ")
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.socket_id, timeout=30)

            if bsdSetSocketOpt:
                self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(socket_fd=self.socket_id, option_name=option_name, option_val=option_val,
                                                   )

            logger().error(f"\n **** Start validation of socket data transfer in rejoin scenario with AP turn off & "
                           f"Turn on again ****\n")
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time:
                send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=self.data,
                                                                         timeout=120)
                logger().info(f'SEND-Bytes = {send_bytes}')
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=self.data,
                                                                             timeout=120)
                    logger().info(f'SEND-Bytes = {send_bytes}')

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    self.switch.interfaces.pdu_switch.turn_off(delay=20)

                    logger().info('******* Turn on Access point **********')
                    self.switch.interfaces.pdu_switch.turn_on(delay=60)
                    check_flag = True
            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id)

    def delta_between_probe_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff

    def delta_btwn_last_beacon_and_first_probe_req(self, dut_mac_address=None, ap_bssid=None, test_case=None):
        """ Method to calculate time stamp for the last beacon and consecutive broadcast and unicast probe request"""
        remote_capture_file = self.wifi_sniffer.interfaces.capture.remote_capture_file
        logger().info(f"capture file is:{remote_capture_file}")

        filter_files = "/tmp/filter_files"
        filtered_file = f'{filter_files}/{test_case}_main_filter.pcap'
        self.wifi_sniffer.interfaces.capture.shell(
            f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")

        filter1 = f'tshark -r {remote_capture_file} -Y "(wlan.addr eq {dut_mac_address}) or (wlan.addr eq {ap_bssid})" -w {filtered_file}'
        logger().info("Creating filtered packets")
        self.wifi_sniffer.interfaces.capture.shell(filter1)

        logger().info("Getting last beacon from the filtered file")
        filter2 = f'tshark -r {filtered_file} -Y "wlan.fc.type_subtype eq 8" -Tfields -e "wlan.fc.type_subtype" -e "frame.time" -e "frame.time_relative" | tail -1'
        last_beacon_time = float(self.wifi_sniffer.interfaces.capture.shell(filter2)[1].split()[-1])
        logger().info(f"last_beacon_time: {last_beacon_time} seconds")

        logger().info("Getting uni-cast probe_requests from the filtered file")
        filter3 = f'tshark -r {filtered_file} -Y "(wlan.fc.type_subtype eq 4 && wlan.da=={ap_bssid})" -Tfields -e "wlan.fc.type_subtype" -e "frame.time" -e "frame.time_relative" > {filter_files}/{test_case}_uni_cast.txt'
        self.wifi_sniffer.interfaces.capture.shell(filter3)

        logger().info("Getting broad_cast probe_requests from the filtered file")
        filter4 = f'tshark -r {filtered_file} -Y "(wlan.fc.type_subtype eq 4 && wlan.da==ff:ff:ff:ff:ff:ff)" -Tfields -e "wlan.fc.type_subtype" -e "frame.time" -e "frame.time_relative" > {filter_files}/{test_case}_broadcast.txt'
        self.wifi_sniffer.interfaces.capture.shell(f"{filter4}; sudo chmod +777 {filter_files}/*")

        if isinstance(self.wifi_sniffer.interfaces.capture.shell, SSHShell):
            with self.wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
                sftp_main.get(filtered_file, f"./reports/{test_case}_delta_filter.pcap")
                uni_cast_file = f"./reports/{test_case}_uni_cast.txt"
                broadcast_file = f"./reports/{test_case}_broadcast.txt"
                sftp_main.get(f"{filter_files}/{test_case}_uni_cast.txt", uni_cast_file)
                sftp_main.get(f"{filter_files}/{test_case}_broadcast.txt", broadcast_file)
                sftp_main.close()

        def get_time(file_name):
            first_probe_time = 0
            with open(file_name) as f:
                for line in f:
                    if float(line.split()[-1]) >= float(last_beacon_time):
                        first_probe_time = float(line.split()[-1])
                        f.close()
                        break
            return first_probe_time

        unicast_probe_time = get_time(uni_cast_file)
        logger().info(f"first unicast_probe_time after last beacon is:{unicast_probe_time} seconds")
        assert unicast_probe_time, "No unicast probe request found from DUT even after AP is switched off"
        time_diff_unicast = int(round((unicast_probe_time - last_beacon_time), 2))
        logger().info(
            f"Time difference between last beacon and first unicast probe request time is: {time_diff_unicast} seconds")

        broadcast_probe_time = get_time(broadcast_file)
        logger().info(f"first broadcast_probe_time after last beacon is:{broadcast_probe_time} seconds")
        if broadcast_probe_time > 0:
            time_diff_broadcast = int(round((broadcast_probe_time - last_beacon_time), 2))
            logger().info(
                f"Time difference between last beacon and first broadcast probe request time is: {time_diff_broadcast} seconds")
        else:
            logger().info("No broadcast probe request found from DUT even after AP is switched off")

    def rejoin_async_event(self):
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        with TimeMeasurer() as t:
            logger().info("Waiting up to 180 seconds for rejoin error event...")
            sw = Stopwatch()
            while sw.elapsed_sec < 180:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                rejoin_error_events = [
                    event
                    for event in events
                    if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT
                ]
                if len(rejoin_error_events):
                    break
                time.sleep(0.1)
            else:
                return False

        logger().info(f"Received rejoin error event after {t.duration:.2f}s")
        return True


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_c19721(switch, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                sl_collections, sniffer_filter):
    """Stop rejoin process by issuing Disconnect command and then do scan and join to the network If Module stops rejoin
         process and gives success message to host AND If Module join to network after disconnect then PASS else FAIL"""
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19721, sl_collections=sl_collections, switch=switch)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n *** Start sniffer configuration *** \n")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info("***** Turn off Access Point *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="probe_request")
        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        wifi_dut.interfaces.wifi.leave()

        logger().info("***** Turn on Access Point *****")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        logger().info("Joining to AP")
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_max_retry_failure_c19722(switch, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                sl_collections, sniffer_filter):
    """Do scan, Join after rejoin failure and validate Rejoin max retry"""
    test_name = request.node.name
    max_retry_attempts = 4
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19722, sl_collections=sl_collections, switch=switch)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="probe_request")
        time.sleep(5)

        # Validating Probe req broadcast packet
        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['find_packet_num'])

        message = f"Broadcast probe request packet count '{packet_count}' is not equal to one less rejoin value {max_retry_attempts}"
        assert packet_count == (max_retry_attempts - 1), message
        logger().info(
            f"Successfully matched Broadcast probe request packet count:'{packet_count}' to one less than rejoin_max_value:'{max_retry_attempts}'")


        logger().info("****** Access point is going to turn on  ******")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, associated=False,
                                                                 ping_after_power_save=False)

        wlan_obj.socket_obj.socket_data_transfer()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_scan_all_channels_c19723(wifi_sniffer, wifi_access_point, wifi_dut, switch,
                                                  request, sl_collections, sniffer_filter):
    test_name = request.node.name
    dut_add_dict ={}
    channel_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    probe_check_dict = {}
    probe_not_captured_channel_list = []
    channel_bitmap_2_4 = 0

    for count in channel_list_2g:
        channel_bitmap_2_4 += 1 << (count - 1)

    """Check rejoin is happening in All channels(1-11) or not and Verify whether module is sending probe requests in all
       channels or not"""
    try:
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info("Initiating the selective channel scan in dut...")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        time.sleep(5)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "Scan results not found"

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # configure_ip tries to assign IP ADDRESS through DHCP
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)

        # we fetch the ip address and mac_address
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        dut_add_dict['device_ip'] = device_ip
        dut_add_dict['dut_mac_address'] = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(
            f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']} DUT IP ADDRESS : {dut_add_dict['device_ip']}")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=30)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list_2g}\n\n")
        for channel in channel_list_2g:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_add_dict['dut_mac_address'],
                                                                                filter_name="probe_request")

            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            probe_check_dict[channel] = int(output)

            logger().info(f'\n\n ***** probe check dictionary : {probe_check_dict} ***** \n\n')
            for key, value in probe_check_dict.items():
                if value == 0:
                    probe_not_captured_channel_list.append(key)

            logger().info(f"probe not captured channel list: {probe_not_captured_channel_list}")
            assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
            logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_selected_channel_c19725(wifi_sniffer, wifi_access_point, wifi_dut, switch,
                                                 request, sl_collections, sniffer_filter):
    test_name = request.node.name
    dut_add_dict ={}
    channel_list_2g = [1, 6, 11]
    probe_check_dict = {}
    probe_not_captured_channel_list = []
    channel_bitmap_2_4 = 0

    for count in channel_list_2g:
        channel_bitmap_2_4 += 1 << (count - 1)

    """Check rejoin is happening in All channels(1-11) or not and Verify whether module is sending probe requests in all
       channels or not"""
    try:
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        logger().info("Initiating the selective channel scan in dut...")

        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None, scan_bitmap_2_4=channel_bitmap_2_4)
        time.sleep(5)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "Scan results not found"

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        # configure_ip tries to assign IP ADDRESS through DHCP
        ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=20)

        # we fetch the ip address and mac_address
        device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        dut_add_dict['device_ip'] = device_ip
        dut_add_dict['dut_mac_address'] = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(
            f"DUT MAC ADDRESS :  {dut_add_dict['dut_mac_address']} DUT IP ADDRESS : {dut_add_dict['device_ip']}")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=30)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list_2g}\n\n")
        for channel in channel_list_2g:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_add_dict['dut_mac_address'],
                                                                                filter_name="probe_request")

            output = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count']
            probe_check_dict[channel] = int(output)

            logger().info(f'\n\n ***** probe check dictionary : {probe_check_dict} ***** \n\n')
            for key, value in probe_check_dict.items():
                if value == 0:
                    probe_not_captured_channel_list.append(key)

            logger().info(f"probe not captured channel list: {probe_not_captured_channel_list}")
            assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
            logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_max_retry_failure_with_security_mode_change_c19729(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                            switch, utf_constants, request,
                                                                            sl_collections, sniffer_filter):
    test_name = request.node.name
    max_retry_attempts = 4
    time_period = utf_constants.get("time_period")

    """Verify rejoin functionality by changing connected AP security settings in 2.4Ghz"""
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19729, sl_collections=sl_collections, switch=switch)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_event_security_change_")
        time.sleep(2)

        logger().info("Changing the PSK of AP")
        wifi_access_point.interfaces.wifi.start_ap(security=SecurityMode.WPA2Enterprise)

        """validate rejoin retry failure"""
        wlan_obj.rejoin_async_event()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="probe_request")

        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['find_packet_num'])

        message = f"Broadcast probe request packet count '{packet_count}' is not equal to one less rejoin value {max_retry_attempts}"
        assert packet_count == (max_retry_attempts - 1), message
        logger().info(
            f"Successfully matched Broadcast probe request packet count:'{packet_count}' to one less than rejoin_max_value:'{max_retry_attempts}'")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_disable_c19733(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants, request,
                                        sl_collections, sniffer_filter):
    test_name = request.node.name
    rejoin_max_value = 20
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19733, sl_collections=sl_collections, switch=switch)

    """Verify default number of retries in rejoin procedure, expecting 19 broadcast packet after Turn off Access point"""
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("\n\n ****** Access point is going to turn off and waiting for Rejoin Error from DUT ******")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_event_")

        """validate rejoin retry failure"""
        wlan_obj.rejoin_async_event()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter\
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="probe_request")

        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['find_packet_num'])

        message = f"Broadcast probe request packet count '{packet_count}' is not equal to one less rejoin value " \
                  f"{rejoin_max_value}"
        assert packet_count == (rejoin_max_value - 1), message
        logger().info(
            f"Successfully matched Broadcast probe request packet count:'{packet_count}' to one less than "
            f"rejoin_max_value:'{rejoin_max_value}'")

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_psk_change_c19734(switch, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                           sl_collections, sniffer_filter):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19729, sl_collections=sl_collections, switch=switch)

    """Verify rejoin procedure when connected AP, PSK got changed"""
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_event_passcode_change_")
        time.sleep(2)

        logger().info('******* Changing the passphrase in Access point **********')
        wifi_access_point.interfaces.wifi.start_ap(passphrase="87654321")

        """validate rejoin retry failure"""
        wlan_obj.rejoin_async_event()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'],
            filter_name="probe_request")

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast packet'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_with_disconnect_c19735(switch, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request,
                                           sl_collections, sniffer_filter):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19735, sl_collections=sl_collections, switch=switch)

    """Issue Disconnect command when module does not find AP in rejoin procedure when first time retry enable bit and
           number of retries to infinite"""
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=120)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.dut_addr['dut_mac_address'],
                                                                            filter_name='probe_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast packet'

        logger().info('************Disconnect the DUT from AP*******************')
        wifi_dut.interfaces.wifi.leave()
        logger().info("******** Turn on the access point ********")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        logger().info("Joining into wifi_access_point")
        sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                            associated=False)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_beacon_miss_counter_c19736(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants,
                                                    request, sl_collections, sniffer_filter):
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19736, sl_collections=sl_collections, switch=switch)

    """ Verify beacon miss counter is resetting or not after AP finding in rejoin process """
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        '''Post AP power off, DUT will try for the rejoin process that we can check in sniffer(i.e: post power off AP need
        to check in sniffer whether the DUT is sending broadcast probe requests or not'''

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=120)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        logger().info(
            "Validating time difference between last beacon received and first unicast and broadcast probe request from DUT")
        wlan_obj.delta_btwn_last_beacon_and_first_probe_req(dut_mac_address=wlan_obj.dut_addr['dut_mac_address'],
                                                            ap_bssid=ap_bssid, test_case="test_19736_counter1")

        # Again checking the time difference between last beacon received and first unicast & broadcast probe request
        logger().info("Start sniffer capture again")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_beacon_miss_counter_19736_2')
        time.sleep(5)
        logger().info('******* Turn on Access point **********')
        logger().info(
            "\n\n****** Wait... for 120 seconds, AP radio turn on and broadcast probe request from DUT ******")
        switch.interfaces.pdu_switch.turn_on(delay=120)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=120)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        logger().info(
            "Again validating time difference between last beacon received and first unicast and broadcast probe request from DUT")
        wlan_obj.delta_btwn_last_beacon_and_first_probe_req(dut_mac_address=wlan_obj.dut_addr['dut_mac_address'],
                                                            ap_bssid=ap_bssid, test_case="test_19736_counter2")

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_scan_interval_1sec_c19737(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants,
                                                   request, sl_collections, sniffer_filter):
    test_name = request.node.name
    scan_interval = 1
    packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
    time_delta = 1
    status = False
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19737, sl_collections=sl_collections, switch=switch)

    """Set scan interval to 1 sec in rejoin params command Verify scan interval time in rejoin process"""
    try:

        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_scan_interval_1_sec_")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off()

        """validate rejoin retry failure"""
        wlan_obj.rejoin_async_event()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_dut.interfaces.wifi.associated = False

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name='probe_request')
        result = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1, packet_filter2=packet_filter2)[
            'packet_count']
        probe_packets_time_delta_list = wlan_obj.delta_between_probe_packet()
        logger().info(f'Probe packet time delta list= {probe_packets_time_delta_list}')

        probe_packets_time_delta_list.pop(0)
        logger().info(f'Probe packet time delta list after removing 0 = {probe_packets_time_delta_list}')
        for time_diff in probe_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(time_delta, time_delta + 2)
            if is_between is False:
                logger().info(is_between)
                status = is_between
                break
            else:
                logger().info(is_between)
                status = is_between
        '''If time gap between 2 successful broadcast packets is ~1sec then PASS else FAIL'''
        if result and status is True:
            logger().info(f'Expected scan interval {scan_interval}sec found between Probe request packets')
            assert True
        else:
            logger().info(f'Expected scan interval {scan_interval}sec not found between Probe request packets')
            assert False

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.skip
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_infinite_retry_c19738(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants,
                                               request, sl_collections, sniffer_filter):
    max_retry_attempts = 0
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19738, sl_collections=sl_collections, switch=switch)

    """Verify rejoin functionality by setting number of retries to infinite"""
    """bsdSetSocketOpt API is not working
    HostSerialConnectionAsync - RX: bsd_socket.set_sock_opt 0 SO_RCVTIMEO 1\r\nNot supported\r\n\r\n>
    """
    try:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=max_retry_attempts, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)
        logger().info("Joining into wifi_access_point")
        socket_obj.wifi_join()

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
        logger().info(f"Setting the tcp retry count for the socket_id->{tcp_socket_id} to {SocketOptions.TCP_MAX_RETRY}"
                      f" seconds")
        socket_obj.socket_data_transfer(set_socket_opt=True)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)

        # '''Verify first scenario, data transfer should resume once it is reconnected to the AP '''
        wifi_sniffer.interfaces.capture.start_capture(capture_file='rejoin_max_retry_validation')

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time_sec:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes, timeout=60)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if b"-1" in send_response:
                    try:
                        wifi_dut.interfaces.wifi.wlan_get_status()
                    except:
                        wifi_dut.interfaces.wifi.wlan_get_socket_info()
                        break
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes, timeout=60)
                    logger().info(f'SEND-RESPONSE = {send_response}')
                    if b"-1" in send_response:
                        try:
                            wifi_dut.interfaces.wifi.wlan_get_status()
                        except:
                            wifi_dut.interfaces.wifi.wlan_get_socket_info()
                            break
                    time.sleep(1)

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    switch.interfaces.pdu_switch.turn_off(delay=20)

                    logger().info('******* Turn on Access point **********')
                    switch.interfaces.pdu_switch.turn_on(delay=30)
                    check_flag = True
        time.sleep(5)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off()

        # validate rejoin retry failure
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == Si91xAsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is not expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 0, f"rejoin fail event found from DUT which is not expected as per test step"

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=mac_address,
                                                                            filter_name='probe_request')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast probe request packet'

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_with_bgscan_c19739(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants, request,
                                            sl_collections, sniffer_filter):

    test_name = request.node.name
    time_period = utf_constants.get("time_period")
    ping_count = 20
    """ Re-join with infinite retry when bgscan enable"""

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19739, sl_collections=sl_collections, switch=switch)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(2)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_bgscan_rejoin_")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                            filter_name='probe_request')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'


        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_wifi_sdk_rejoin_first_time_retry_c19740(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants,
                                                 request, sl_collections, sniffer_filter):
    """Verify first time retry functionality when AP sends de-auth frame while connecting"""
    max_retry_attempts = 4
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19740, sl_collections=sl_collections, switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(5)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name='eapol_m2_after_deauth')
        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['find_packet_num'])

        message = f"Rejoin retry value:'{max_retry_attempts}' is not equal to No of M2 packet count:'{packet_count}'"
        assert packet_count == max_retry_attempts, message
        logger().info(
            f"Rejoin retry value:'{max_retry_attempts}' is equal to No of M2 packet count:'{packet_count}'")
        wifi_dut.interfaces.wifi.associated = False

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'Hidden_SSID_C19741', "broadcast_ssid": False})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)

def test_wifi_sdk_rejoin_hidden_ssid_c19741(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants, request,
                                            sl_collections, sniffer_filter):
    """Rejoin functionality with hidden mode AP"""
    ping_count = 20
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19741, sl_collections=sl_collections, switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter\
            (sa_addr=wlan_obj.dut_addr['dut_mac_address'], filter_name="probe_request")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        logger().info("\n\n Adding sleep for 10 sec \n")
        time.sleep(20)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info("Turn on Access Point")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "US", "channel": 11})
def test_wifi_sdk_rejoin_in_us_region_c19742(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants, request,
                                             sl_collections, sniffer_filter):
    """ Verify Rejoin Functionality with US region enabled in 2.4GHZ band"""
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19742, sl_collections=sl_collections, switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_rejoin_us_region")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        wlan_obj.socket_data_transfer_recovery_in_rejoin(bsdSetSocketOpt=False)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        filter_name='probe_request')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], 20)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Europe", "channel": 11})
def test_wifi_sdk_rejoin_in_eu_region_c19743(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants, request,
                                             sl_collections, sniffer_filter):
    """Verify Rejoin Functionality with EU region enabled in 2.4GHZ band"""
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19743, sl_collections=sl_collections, switch=switch)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(2)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_bgscan_rejoin_")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        filter_name='probe_request')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], 20)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Europe", "channel": 13})
def test_wifi_sdk_rejoin_in_japan_region_c19744(wifi_access_point, wifi_sniffer, wifi_dut, switch, utf_constants,
                                                request, sl_collections, sniffer_filter):
    """ Verify Rejoin Functionality with JP region enabled in 2.4GHZ band,
        # Please Note - ASUS AP doesn't have Japan region, So changed to US region"""
    test_name = request.node.name
    time_period = utf_constants.get("time_period")


    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19744, sl_collections=sl_collections, switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_rejoin_japan_region")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        wlan_obj.socket_data_transfer_recovery_in_rejoin(bsdSetSocketOpt=False)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        filter_name='probe_request')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], 20)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Asia", "channel": 11})
def test_wifi_sdk_rejoin_in_worldwide_region_c19745(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants,
                                                    request, sl_collections, sniffer_filter):
    """ Verify Rejoin Functionality with world mode region enabled in 2.4GHZ band"""
    test_name = request.node.name
    time_period = utf_constants.get("time_period")


    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19745, sl_collections=sl_collections, switch=switch)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        time.sleep(2)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="test_rejoin_wordwide_region_")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=wlan_obj.
                                                                                        dut_addr['dut_mac_address'],
                                                                                        filter_name='probe_request')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping(wlan_obj.dut_addr['device_ip'], 20)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


# EAP Connection in TLS mode
# @pytest.mark.start_state("wifi_dut", wifi="init")
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.config('wifi_access_point',
#                     wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "clear_certs"])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
#         "oper_mode": Si91xOperatingMode.EAPWiFiClient,
#         "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
#         "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake
#                     | Si91xFeatureBitMap.Aggregation,
#         "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
#         "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid | Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost,
#         "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower
#                                | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
#                                | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
#         "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
#                               | Si91xCertificateType.EAPClientCertificate,
#         "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
#                            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
#         "tx_wait_time": 16000,
#         "band": 0,
#         "eap_cert": "wifi-user.pem",
#         "bt_features": 0,
#         "ble_features": 0,
#         "ble_custom_ext_features": 0,
# },
# )
# def test_wifi_sdk_rejoin_eap_tls_c19730(switch, wifi_sniffer, wifi_access_point, wifi_dut, radius_server,
#                                         utf_constants, request, sl_collections, sniffer_filter):
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                            Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0|
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_rejoin_eap_tls_c19730(wifi_dut, wifi_access_point, wifi_sniffer, radius_server, request, sl_collections, switch):
    """Verify rejoin functionality in EAP-TLS mode"""
    test_name = request.node.name
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19730, sl_collections=sl_collections,
                          switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


# EAP Connection in TTLS mode
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                            Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0|
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])
def test_wifi_sdk_rejoin_eap_ttls_c19731(switch, wifi_sniffer, wifi_access_point, wifi_dut, radius_server, request, sl_collections):
    """Verify rejoin functionality in EAP-TTLS mode"""
    test_name = request.node.name
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          test_name=test_name, test_case_no=19731,
                          sl_collections=sl_collections, switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

# EAP Connection in PEAP mode
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": Si91xOperatingMode.EAPWiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.PSKSecurity | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP |
                            Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0|
                                Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "band": 0,
        "eap_cert": ["wifi-user.pem", "SL_NET_EAP_CLIENT_CREDENTIAL", "SL_NET_WIFI_EAP_CLIENT_CREDENTIAL_ID"]

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated", "wifi_powersave_disable", "bt_powersave_disable", "clear_certs"])

def test_wifi_sdk_rejoin_eap_peap_c19732(switch, wifi_sniffer, wifi_access_point, wifi_dut, radius_server,
                                         request, sl_collections):
    """Verify rejoin functionality in EAP-, PEAP mode"""
    test_name = request.node.name
    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                          time_period=time_period, test_name=test_name,
                          test_case_no=19732, sl_collections=sl_collections, switch=switch, data_transfer=False)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tx_wait_time": 16000,
        }
)
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'rejoin_roaming_c19728',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 11
        },
        1: {
            'ssid': 'rejoin_roaming_c19728',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 11
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_rejoin_roaming_c19728(wifi_access_points, wifi_dut, switches, wifi_sniffer, utf_constants, request):
    test_name = request.node.name
    max_retry_attempts = 0
    ping_count = 120
    end_time = utf_constants.get("time_duration")
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data, switch=switch)

    try:
        '''Verify Module functionality if de-auth receives after roaming to new AP'''
        logger().info('******* Turn off AP0 outlet  **********')
        switches[0].interfaces.pdu_switch.turn_off()
        state = switches[0].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP0: " + str(state))
        assert state == 'false', 'Please check PDU outlet manually'
        logger().info('******* Turn on AP1 outlet  **********')
        state = switches[1].interfaces.pdu_switch.get_state()
        if state == 'false':
            switches[1].interfaces.pdu_switch.turn_on()
            state = switches[1].interfaces.pdu_switch.get_state()
            logger().info("pdu switch state for AP1: " + str(state))
            assert state == 'true', 'Please check PDU outlet manually'
        elif state == 'true':
            logger().info('******* AP1 outlet is already turn on **********')

        time.sleep(10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='rejoin_AP1')
        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=25, trigger_level_change=4)

        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=max_retry_attempts, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[1])

        result = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = result.ip.decode()
        logger().info(f"DUT ip address : {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid_1 = wifi_access_points[1].interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid_1}')

        wifi_status = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here=======>>>>>>>>>the wifi_status is as follows:{wifi_status}")

        rssi_value = wifi_dut.interfaces.wifi.wlan_get_rssi()
        logger().info(f'\n\n RSSI Value = {rssi_value}\n')

        logger().info(f"*****Enable Max PSP in DUT******")
        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(Si91xPowerSaveModes.PowerSaveMode2,
                                                             Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(Si91xPowerSaveModes.PowerSaveMode2,
                                                              Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"

        logger().info(f"Initiating ping to DUT ip {dut_ip} after power save")
        ping(dut_ip, ping_count)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            sta_mac_address=ap_bssid_1,
                                                                            filter_name='assoc_req_resp')

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            sta_mac_address=ap_bssid_1,
                                                                            filter_name='power_mgmt_bit')

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find Association req & Association response packet'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find PWMT bit enable'

        '''Enable first AP0 which is near to DUT, DUT should automatically connect with AP1'''
        switches[0].interfaces.pdu_switch.turn_on()
        state = switches[0].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP0: " + str(state))
        assert state == 'true', 'Please check PDU outlet manually'

        switches[1].interfaces.pdu_switch.turn_off()
        state = switches[1].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP1: " + str(state))
        assert state == 'false', 'Please check PDU outlet manually'

        time.sleep(10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='rejoin_AP0')

        '''Expecting AP0 will automatically connect with DUT'''
        sw = Stopwatch()
        end_time = 120
        connection_flag = False
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            connect_events = [event for event in events if event.event_type == Si91xAsyncEventType.Connect]
            if len(connect_events):
                logger().info(f'DUT is successfully connected to AP0')
                connection_flag = True
                break
        assert connection_flag == True, 'DUT unable to make connection with AP0 with in 120 seconds'

        ap_bssid_0 = wifi_access_points[0].interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid_0}')

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        status = socket_obj.ping_to_dut(ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        wifi_access_points[0].interfaces.wifi.stop_ap()
        time.sleep(10)

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_bssid_0,
                                                                            filter_name='deauthentication')

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'Unable to find Deauth packet'

        '''Turn on AP1 to validate again, DUT should reconnect with AP1'''
        switches[1].interfaces.pdu_switch.turn_on()
        state = switches[1].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP1: " + str(state))

        assert state == 'true', 'Please check PDU outlet manually'

        '''Expecting AP1 will automatically connect with DUT'''
        connection_flag = False
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            connect_events = [event for event in events if event.event_type == Si91xAsyncEventType.Connect]
            if len(connect_events):
                logger().info(f'DUT is successfully connected to AP0')
                connection_flag = True
                break
            assert connection_flag == True, 'DUT unable to make connection with AP1 with in 120 seconds'

        wifi_status = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here=======>>>>>>>>>the wifi_status is as follows:{wifi_status}")
        rssi_value = wifi_dut.interfaces.wifi.wlan_get_rssi()
        logger().info(f'\n\n RSSI Value = {rssi_value}\n')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5', '0x0025']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        '''Finally turn on the AP0 for next test cases'''
        logger().info(f'\n\n ***** Going to turn on AP0 ***** n\n')
        switches[0].interfaces.pdu_switch.turn_on()
        state = switches[0].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP0: " + str(state))
        assert state == 'true', 'Please check PDU outlet manually'

        logger().info(f'\n\n ***** Going to turn off AP1 ***** n\n')
        switches[1].interfaces.pdu_switch.turn_off()
        state = switches[1].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP1: " + str(state))

        assert state == 'false', 'Please check PDU outlet manually'
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.skip
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tx_wait_time": 16000,
        }
)
@pytest.mark.config(
    "wifi_access_points",
    wifi={
        # Here, indexing (starts with 0) applies as per order defined in harness.
        0: {
            'ssid': 'rejoin_roaming_c1976',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 11
        },
        1: {
            'ssid': 'rejoin_roaming_c19726',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 1
        }
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wifi_sdk_rejoin_roaming_c19726(wifi_access_points, wifi_dut, switches, wifi_sniffer, request):
    test_name = request.node.name
    validation = True
    rejoin_value = 0
    ping_count = 120
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, end_time=end_time,
                                    data=data, switch=switch)
    try:
        '''Verify whether module is connecting to better RSSI AP when module found 2 Aps With same SSID and same
           settings in rejoin process'''
        logger().info('******* Turn off AP0 outlet  **********')
        switches[0].interfaces.pdu_switch.turn_off()
        state = switches[0].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP0: " + str(state))
        assert state == 'false', 'Please check PDU outlet manually'

        logger().info('******* Turn on AP1 outlet  **********')
        state = switches[1].interfaces.pdu_switch.get_state()
        if state == 'false':
            switches[1].interfaces.pdu_switch.turn_on()
            state = switches[1].interfaces.pdu_switch.get_state()
            logger().info("pdu switch state for AP1: " + str(state))
            assert state == 'true', 'Please check PDU outlet manually'
        elif state == 'true':
            logger().info('******* AP1 outlet is already turn on **********')

        time.sleep(10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[1].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='rejoin_AP1')

        wifi_dut.interfaces.wifi.set_roam_configuration(trigger_level=25, trigger_level_change=4)

        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                 beacon_missed_count=40, first_time_retry_enable=0)

        logger().info("Joining into wifi_access_point")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_points[1])

        result = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = result.ip.decode()
        logger().info(f"DUT ip address : {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid_1 = wifi_access_points[1].interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid_1}')

        wifi_status = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here=======>>>>>>>>>the wifi_status is as follows:{wifi_status}")

        rssi_value = wifi_dut.interfaces.wifi.wlan_get_rssi()
        logger().info(f'\n\n RSSI Value = {rssi_value}\n')

        logger().info(f"*****Enable Max PSP in DUT******")
        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(Si91xPowerSaveModes.PowerSaveMode2,
                                                             Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(Si91xPowerSaveModes.PowerSaveMode2,
                                                              Si91xPowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"

        logger().info(f"Initiating ping to DUT ip {dut_ip} after power save")
        ping(dut_ip, ping_count)

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            sta_mac_address=ap_bssid_1,
                                                                            filter_name='assoc_req_resp')

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                            sta_mac_address=ap_bssid_1,
                                                                            filter_name='power_mgmt_bit')

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count'], 'Unable to find Association req & Association response packet'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count'], 'Unable to find PWMT bit enable'

        '''Enable first AP0 which is near to DUT, DUT should automatically connect with AP1'''
        switches[0].interfaces.pdu_switch.turn_on()
        state = switches[0].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP0: " + str(state))
        assert state == 'true', 'Please check PDU outlet manually'

        switches[1].interfaces.pdu_switch.turn_off()
        state = switches[1].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP1: " + str(state))
        assert state == 'false', 'Please check PDU outlet manually'

        time.sleep(10)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_points[0].interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='rejoin_AP0')

        '''Expecting AP0 will automatically connect with DUT'''
        sw = Stopwatch()
        end_time = 120
        connection_flag = False
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            connect_events = [event for event in events if event.event_type == Si91xAsyncEventType.Connect]
            if len(connect_events):
                logger().info(f'DUT is successfully connected to AP0')
                connection_flag = True
                break
        assert connection_flag == True, 'DUT unable to make connection with AP0 with in 120 seconds'

        ap_bssid_0 = wifi_access_points[0].interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid_0}')

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f'DUT ip {device_ip}')

        status = ping(device_ip, ping_count)
        assert status == 1, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        wifi_access_points[0].interfaces.wifi.stop_ap()
        time.sleep(10)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=ap_bssid_0,
                                                                            filter_name='deauthentication')

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count'], 'Unable to find Deauth packet'

        '''Turn on AP1 to validate again, DUT should reconnect with AP1'''
        switches[1].interfaces.pdu_switch.turn_on()
        state = switches[1].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP1: " + str(state))
        assert state == 'true', 'Please check PDU outlet manually'

        '''Expecting AP1 will automatically connect with DUT'''
        connection_flag = False
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            connect_events = [event for event in events if event.event_type == Si91xAsyncEventType.Connect]
            if len(connect_events):
                logger().info(f'DUT is successfully connected to AP0')
                connection_flag = True
                break
            assert connection_flag == True, 'DUT unable to make connection with AP1 with in 120 seconds'

        wifi_status = wifi_dut.interfaces.wifi.get_wireless_info()
        logger().info(f"here=======>>>>>>>>>the wifi_status is as follows:{wifi_status}")
        rssi_value = wifi_dut.interfaces.wifi.wlan_get_rssi()
        logger().info(f'\n\n RSSI Value = {rssi_value}\n')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5', '0x0025']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        '''Finally turn on the AP0 for next test cases'''
        switches[0].interfaces.pdu_switch.turn_on()
        state = switches[0].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP0: " + str(state))
        assert state == 'true', 'Please check PDU outlet manually'

        switches[1].interfaces.pdu_switch.turn_off()
        state = switches[1].interfaces.pdu_switch.get_state()
        logger().info("pdu switch state for AP1: " + str(state))
        assert state == 'false', 'Please check PDU outlet manually'
        wifi_dut.interfaces.wifi.leave()


