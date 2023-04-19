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
lock = threading.RLock()

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

ping_count = 120


# this thread used for wifi join
class traffic_generator:

    def __init__(self, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, device_ip=None, host_ip=None, timeout=60):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip
        self.timeout = timeout
        self.dut_mac_address = None
        self.ap_bssid = None

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_rx(self):
        # preparing iperf
        self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip, device_ip=self.device_ip,
                                                             host_role="C", protocol=self.protocol,
                                                             time_out=self.timeout)

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



class eap_join:

    def __init__(self, wifi_dut=None, wifi_access_point=None, eap_type="TLS"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.eap_type = eap_type

    # Join Wi-Fi Access Point
    def join_ap(self):
        if self.eap_type != "TLS":
            self.wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

        self.wifi_dut.interfaces.wifi.eap_join_ap(self.wifi_access_point, eap_method=self.eap_type,
                                                  timeout=40)



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

    def run_traffic(self):

        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{self.host_ip}")

        logger().info("starting the server from Remote device")

        for self.protocol in self.protocols:

            for self.traffic_type in self.traffic_types:

                tg = traffic_generator(self.wifi_dut, self.wifi_access_point, self.wifi_client,
                                       self.net_perf_client, self.protocol, self.device_ip, self.host_ip)

                if self.traffic_type == "TX":
                    # starting iperf
                    tg.run_tx()
                if self.traffic_type == "RX":
                    tg.run_rx()

        logger().info("data transfer is successful")

    def run(self):

        with lock:
            ej = eap_join(self.wifi_dut, self.wifi_access_point, self.eap_type)
            ej.join_ap()
            for count in range(1, 4):
                try:
                    ip_config = self.wifi_dut.interfaces.wifi.start_ip()
                    assert isinstance(ip_config,
                                      self.wifi_dut.interfaces.wifi.IPConfig), \
                        f"Failed to get IP address. Result = {ip_config}"
                    self.device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                    break
                except Exception as e:
                    logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}"
                                  f"\n Exception: {e}")
                    time.sleep(10)
            assert self.device_ip, "ip setting in DUT has failed"
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
        if self.net_perf_client:
            ping_count = 10
        else:
            ping_count = 100

        for count in range(3):
            try:
                logger().info("pinging to dut after power-save.....")
                status = ping(self.device_ip, ping_count)
                assert status == 1, "DUT not responding for ping request......"
                logger().info("ping to DUT is successful....")
                break
            except Exception as e:
                logger().info(f"ping to dut is failed...retry count->{count + 1}"
                              f"\n Exception: {e}")

        if self.net_perf_client:
            self.run_traffic()

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(10)


    def verify_sniffer_validation(self):

        validation = True

        packet_filter = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter2 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"

        # Validating the EAP failure frames
        packet_filter3 = f"wlan.addr=={self.dut_mac_address} && eap|| eapol"

        packet_filter4 = f"wlan.addr=={self.ap_bssid} && eap || eapol"

        packet_filter5 = f'wlan.ra == {self.dut_mac_address} and wlan.ta == {self.ap_bssid} and ' \
                         f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr=={self.dut_mac_address} and wlan.fc.type_subtype==0x001a and wlan.fc.pwrmgt==1'

        # logger().info(
        #     f"Validating probe reqs from DUT"
        # )
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

        logger().info(f"Validating QOS  data frames with more data bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find more data bit set in QOS Data frames in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

        logger().info("Successfully validated sniffer packets")



# this thread used for sta+ble as a slave
class BleThread_Advertise(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, adv_int=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = adv_int
        self.bt_dut_address = None


    def stop_adv_scan(self):
        logger().info("Initiating stop advertise from DUT")
        self.wifi_dut.interfaces.wifi.ble_stop_advertising()
        logger().info("Initiating stop scan from Remote device")
        self.ble_client.interfaces.bluetooth.stop_scanning()

    def run(self):
        with lock:
            # Set up DUT for BLE advertising
            logger().info("Initialising BLE")
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"
            logger().info(f"bt_dut_address : {self.bt_dut_address}")
            time.sleep(5)
            logger().info(f"Advertising the DUT")
            if self.adv_int:
                self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=int(self.adv_int / 0.625),
                                                                    ble_adv_int_max=int(self.adv_int / 0.625), timeout=30)
            else:
                self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)

        logger().info("Initiating scan from Remote device")
        # Begin Scanning for BLE devices
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
        assert bt_client_address is not None, "Unable to fetch bluetooth address from Remote device"
        logger().info(f"Started scan from remote BLE device")
        logger().info("\n***********{}**********\n".format(bt_client_address))
        for i in range(0, 3):
            time.sleep(20)
            if self.adv_int:
                if self.adv_int > 1000:
                    time.sleep(20)
            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info("\n***scan results:{}**********\n".format(found_devices))

        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"

# this thread used for sta+ble as a slave
class BleThread_Connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode
        self.bt_dut_address = None
        self.bt_client_address = None

    def disconnect(self):

        if self.mode == "ble_master":
            logger().info(f"Initiating disconnect...")
            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address)
            logger().info("Initiating stop scan from Remote device")
            self.ble_client.interfaces.bluetooth.stop_scanning()

        if self.mode == "ble_slave":
            logger().info("Initiating disconnect from remote device")
            self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)
            logger().info(f"*****BLE sniffer validation is pending*******")

    def run(self):

        with lock:
            # Set up DUT for BLE advertising
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"

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
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address, timeout=30)
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()

                logger().info(f"Initiating connection...")
                self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.bt_client_address, timeout=120)
                time.sleep(60)
                # Get the state of the dut
                state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
                logger().info(f"Getting device state : {state} ")
                # state_int = int(state) if state.isdigit() else -1
                # assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in slave mode"
                # logger().info(f"Dut is in connected state {state_int}")

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
                time.sleep(60)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_TLS_BLE_adv_C133461(radius_server, wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_TLS_BLE_adv_C133461"
    logger().info("testcase : test_sta_ble_TLS_BLE_adv_C133461")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          eap_type="TLS", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
    wifi_obj.stop()
    ble_obj.stop()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_TTLS_BLE_adv_C133462(radius_server, wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_TTLS_BLE_adv_C133462"
    logger().info("testcase : test_sta_ble_TTLS_BLE_adv_C133462")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          eap_type="TTLS", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
    wifi_obj.stop()
    ble_obj.stop()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_PEAP_BLE_adv_C133463(radius_server, wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_PEAP_BLE_adv_C133463"
    logger().info("testcase : test_sta_ble_PEAP_BLE_adv_C133463")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          eap_type="PEAP", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
    wifi_obj.stop()
    ble_obj.stop()




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_disconnect", "clear_certs"])
def test_sta_ble_TCP_UDP_TLS_C133451(radius_server, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, ble_client, net_perf_client):
    testcase = "test_sta_ble_TCP_UDP_TLS_C133451"
    logger().info("testcase : test_sta_ble_TCP_UDP_TLS_C133451")
    validation = True
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    traffic_types = ["RX", "TX"]
    logger().info(f"configuring the Sniffer with the channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Connection(wifi_dut, ble_client, mode="ble_master")
    wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          eap_type="TLS", testcase=testcase,
                          wifi_client=wifi_client, net_perf_client=net_perf_client, protocols=protocols,
                          traffic_types=traffic_types)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    # Disconnect
    ble_obj.disconnect()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
    wifi_obj.stop()
    ble_obj.stop()




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
        | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose
        | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TTLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_disconnect", "clear_certs"])
def test_sta_ble_TCP_UDP_TTLS_C133452(radius_server, wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, ble_client,
                                     net_perf_client):
    testcase = "test_sta_ble_TCP_UDP_TTLS_C133452"
    logger().info("testcase : test_sta_ble_TCP_UDP_TTLS_C133452")
    validation = True
    protocols = [IperfConstants.TCP, IperfConstants.UDP]
    traffic_types = ["RX", "TX"]
    logger().info(f"configuring the Sniffer with the channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Connection(wifi_dut, ble_client, mode="ble_master")
    wifi_obj = WifiThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          eap_type="TTLS", testcase=testcase,
                          wifi_client=wifi_client, net_perf_client=net_perf_client, protocols=protocols,
                          traffic_types=traffic_types)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    logger().info(f"Initiating disconnect...")
    # Disconnect
    ble_obj.disconnect()

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
    wifi_obj.stop()
    ble_obj.stop()
