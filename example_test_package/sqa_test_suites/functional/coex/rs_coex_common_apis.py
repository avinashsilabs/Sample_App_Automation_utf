import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap, RS9116CertificateType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import threading
from threading import *
import time

import test_sta_ble_diff_ble_intervals

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify more data bit to be enable in QOS data frames and power management bit in ps polls
        6. Initiate BLE advertise/scan
        7. Run Iperf data transfer/Download http data

    Author: swathi.pathuri
"""

def logger():
    return get_logger(__name__)


ping_count = 50

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, eap_type="TLS", testcase=None, wifi_client=None, \
                 net_perf_client=None, protocols=None, traffic_types=None, http_server=None, index_path=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.eap_type = eap_type
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocols = protocols
        self.traffic_types = traffic_types
        self.device_ip = None
        self.host_ip = None
        self.dut_mac_address = None
        self.ap_bssid = None
        self.http_server = http_server
        self.index_path = index_path

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def wifi_join(self):

        # Join Wi-Fi Access Point
        if "Enterprise" not in str(self.wifi_access_point.interfaces.wifi.security):

            for count in range(0, 3):
                logger().info("Initiating wlan scan")
                # enables the scan in dut on channel
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                logger().info(f"scan results : {scan_results}")
                assert (len(scan_results) > 0), "scan failed"
                time.sleep(8)

            logger().info("Initiating wlan join")
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        else:
            ap_user_name = "\\\"user1\\\""
            ap_password = f"\\\"{self.wifi_access_point.interfaces.wifi.passphrase}\\\""
            dut_ssid = self.wifi_access_point.interfaces.wifi.ssid
            dut_security = self.wifi_access_point.interfaces.wifi.security

            if self.eap_type != "TLS":
                self.wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

            logger().info("Setting roam parameters")
            # enable Roaming
            self.wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

            logger().info("scanning for AP")

            for count in range(0, 3):
                logger().info("Initiating wlan scan")
                # enables the scan in dut on channel
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                logger().info(f"scan results : {scan_results}")
                assert (len(scan_results) > 0), "scan failed"
                time.sleep(2)
            # test_scan
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,
                                                              ssid=dut_ssid)
            logger().info(scan_results)

            logger().info("enable rejoin")
            self.wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40,
                                                 first_time_retry=0)

            # test_wifi_join
            self.wifi_dut.interfaces.wifi.eap_method(eap_method=self.eap_type, eap_inner_method="\\\"auth=MSCHAPV2\\\"",
                                                     private_key="\"\"")
            self.wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)


    def run_traffic(self):

        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{self.host_ip}")

        logger().info("starting the server from Remote device")

        for self.protocol in self.protocols:

            for self.traffic_type in self.traffic_types:

                if self.traffic_type == "TX":
                    # starting iperf
                    self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip,
                                                                         host_role="S", protocol=self.protocol,
                                                                         time_out=60)
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

                if self.traffic_type == "RX":
                    # preparing iperf
                    self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip, device_ip=self.device_ip,
                                                                         host_role="C", protocol=self.protocol,
                                                                         time_out=60)

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

                logger().info(f"caluculating the throughput for {self.protocol} {self.traffic_type}")

                self.__print_throughput(tp)

        logger().info("data transfer is successful")

    def run(self):

        self.wifi_join()
        # Get IP through DHCP
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        self.device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"Found device ip :{self.device_ip}")

        logger().info("Getting the DUT mac")
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {self.dut_mac_address}")

        self.ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {self.ap_bssid}")

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
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info("ping is successful")

        if self.net_perf_client:
            self.run_traffic()

        if self.http_server:
            time.sleep(20)
            self.run_http_download()


        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    def run_http_download(self):

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        # API used to get the http data
        self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        logger().info(f"Http download is successful")

    def verify_sniffer_validation(self):

        validation = True

        packet_filter = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter2 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"

        # Validating the EAP failure frames
        packet_filter3 = f"wlan.addr=={self.dut_mac_address} && eap|| eapol"

        packet_filter4 = f"wlan.addr=={self.ap_bssid} && eap || eapol"

        packet_filter5 = f'wlan.ta == {self.dut_mac_address} and wlan.ra == {self.ap_bssid} and ' \
                         f'wlan.fc.pwrmgt == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr=={self.dut_mac_address} and wlan.fc.type_subtype==0x001a and wlan.fc.pwrmgt==1'

        logger().info(
            f"Validating probe reqs from DUT"
        )
        # assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)[
        #     'packet_count'], 'Unable to find probe reqs sent from DUT in sniffer '

        logger().info(
            f"Validating association, eapol from DUT"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '

        logger().info(
            f"Validating association, eapol from AP"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '
        if "Enterprise" in str(self.wifi_access_point.interfaces.wifi.security):
            logger().info(
                f"Validating EAP frames in sniffer"
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
                'packet_count'], 'Unable to find EAP frames sent from STA in sniffer '
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
                'packet_count'], 'Unable to find EAP frames sent from AP in sniffer '

        else:

            logger().info(
                f"Validating DHCP frames from AP & DUT"
            )
            decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
            logger().info(f"decryption_key : {decryption_key}")
            dhcp_list = self.wifi_sniffer.interfaces.capture.get_dhcp_list(self.dut_mac_address, decryption_key, ["dhcp"])
            logger().info(f"dhcp_list : {dhcp_list}")
            assert dhcp_list == True, "DHCP packets not found"

        logger().info(f"Validating QOS  NULL data frames with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find power management bit in QOS null frames in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

        logger().info("Successfully validated sniffer packets")



# thread for wifi scan functionality
class WifiScanThread(ThreadBase):
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase
        self.dut_mac_address = None

    def run(self):

        for count in range(0, 3):
            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) > 0), "scan failed"
            time.sleep(2)

        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {self.dut_mac_address}")

    def verify_sniffer_validation(self):
        validation = True

        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        logger().info(
            f"Validating Probe req(Broadcast)"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'


# this thread used for sta+ble as a slave
class BleThread_Advertise(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, adv_int=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = adv_int
        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.bt_dut_address}")
        time.sleep(5)

    def run(self):
        logger().info(f"Advertising the DUT")
        if self.adv_int:
            self.adv_int = int(self.adv_int / 0.625)
            self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=self.adv_int, \
                                                                ble_adv_int_max=self.adv_int, timeout=30)
        else:
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info("Initiating scan from Remote device")
        # Begin Scanning for BLE devices
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
        assert bt_client_address is not None, "Unable to fetch bluetooth address from Remote device"
        logger().info(f"Started scan from remote BLE device")
        logger().info("\n***********{}**********\n".format(bt_client_address))
        for i in range(0, 3):
            time.sleep(10)
            if self.adv_int:
                if self.adv_int > 1000:
                    time.sleep(20)
            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info("\n***scan results:{}**********\n".format(found_devices))

        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"
        logger().info(f"*****Logic Analyzer validation is pending*******")


# this thread used for sta+ble as a slave
class BleThread_Scan(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_scan_interval, ble_scan_window):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_scan_interval = int(ble_scan_interval / 0.625)
        self.ble_scan_window = int(ble_scan_window / 0.625)
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"{self.bt_dut_address}")
        time.sleep(5)

    def run(self):

        logger().info(f"Advertising the Remote BLE device")
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
            bt_dut_address=self.bt_dut_address,
            hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                           "0x40 0x00 "  # Advertising_Interval_Max
                           "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                           "0x00 "  # Own_Address_Type
                           "0x00 "  # Peer_Address_Type
                           "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                           "0x07 "  # Advertising_Channel_Map
                           "0x00"  # Advertising_Filter_Policy
        )
        assert bt_client_address is not None, "Unable to fetch bluetooth address from Remote device"

        logger().info(f"advertised remote BLE device")
        # Start scanning
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, \
                                                         ble_scan_interval=self.ble_scan_interval, \
                                                         ble_scan_window=self.ble_scan_window, timeout=60)

        logger().info(f"Remote device found in scan results ,BLE scanning is successful")
        logger().info(f"*****Logic Analyzer validation is pending*******")



# this thread used for sta+ble as a slave
class BleThread_Connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

        # Set up DUT for BLE advertising
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"

    def disconnect(self):

        if self.mode == "ble_master":
            logger().info(f"Initiating disconnect...")
            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address)

        if self.mode == "ble_slave":
            logger().info("Initiating disconnect from remote device")
            self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
            logger().info(f"*****BLE sniffer validation is pending*******")

    def run(self):
        if self.mode == "ble_master":
            # Start DUT

            # Start ble client
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
                bt_dut_address=self.bt_dut_address,
                hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                               "0x40 0x00 "  # Advertising_Interval_Max
                               "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                               "0x00 "  # Own_Address_Type
                               "0x00 "  # Peer_Address_Type
                               "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                               "0x07 "  # Advertising_Channel_Map
                               "0x00"  # Advertising_Filter_Policy
            )
            assert self.bt_client_address is not None, "Unable to fetch bluetooth address from remote device"
            time.sleep(1)
            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address, timeout=20)
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

            logger().info(f"Initiating connection...")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.bt_client_address, timeout=120)

        if self.mode == "ble_slave":

            logger().info("Initiating advertise from DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            logger().info("Initiating BLE scan from remote device")
            # Begin Scanning for BLE devices
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
            assert self.bt_client_address is not None, "Unable to fetch bluetooth address from remote device"
            time.sleep(5)
            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"

            logger().info("Initiating connection from remote device")
            self.ble_client.interfaces.bluetooth.connect(self.bt_dut_address)

            # self.ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0x28,
            #                                              max_conn_interval=0x28, conn_latency=2,
            #                                              supervision_timeout=16000)

