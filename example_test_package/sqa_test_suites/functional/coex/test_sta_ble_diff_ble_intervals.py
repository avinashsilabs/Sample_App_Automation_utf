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
    RS9116PowerSaveProcedureTypes
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.thread_base import ThreadBase
import threading
from threading import *
import time
import test_sta_ble_enterprise as sbe

def logger():
    return get_logger(__name__)


ping_count = 50

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

class validate_sniffer_functionality:

    def __init__(self, dut_mac_address=None, ap_bssid=None):
        super().__init__()
        self.dut_mac_address = dut_mac_address
        self.ap_bssid = ap_bssid

    def basic_verification(self):

        validation = True

        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter2 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter3 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"

        packet_filter4 = f" (dhcp) && (wlan.addr == {self.ap_bssid}) && (wlan.addr == {self.dut_mac_address})"

        packet_filter5 = f'wlan.da == {self.dut_mac_address} and wlan.ta == {self.bssid} and ' \
                         f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        logger().info(
            f"Validating Probe req(Broadcast)"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'

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

        logger().info(
            f"Validating DHCP frames from AP & DUT"
        )
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        dhcp_list = self.wifi_sniffer.interfaces.capture.get_dhcp_list(self.dut_mac_address, decryption_key, ["dhcp"])
        logger().info(f"dhcp_list : {dhcp_list}")
        assert dhcp_list, "DHCP packets not found"

        logger().info(f"Validating more data bit in QOS data frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find power management bit in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, testcase=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, http_server=None, index_path=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.http_server = http_server
        self.index_path = index_path
        self.device_ip = None
        self.host_ip = None
        self.dut_mac_address = None
        self.ap_bssid = None

    def run_http_download(self):

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        # API used to get the http data
        self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        logger().info(f"Http download is successful")

    def run(self):

        with lock:
            self.ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {self.ap_bssid}")

            logger().info("Initiating wlan scan")
            # enables the scan in dut on channel
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,
                                                              ssid=None)
            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) >= 1), "scan results not found"

            logger().info("Initiating wlan join")
            # Join Wi-Fi Access Point
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info(f"Successfully connected to AP")

            logger().info("Initiating getting dhcp ip")
            # This API Enables the DHCP in DUT
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
            self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"Found device ip: {self.device_ip}")

            # Fetches the DUT mac address
            self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {self.dut_mac_address}")
            # time.sleep(10)
            logger().info("Initiating power save")
            # This API Enables the wifi power save mode in DUT

            self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                     RS9116PowerSaveProcedureTypes.FastPowerSave)
            # # Enables the bt power save in DUT

            self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
            time.sleep(5)

            if self.net_perf_client or self.http_server:
                # Initiate ping from third party wifi-client to DUT
                status = ping(self.device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")

        if not (self.net_perf_client or self.http_server):
                # Initiate ping from third party wifi-client to DUT
                status = ping(self.device_ip, ping_count)
                assert status is True, "DUT is not responding to ping request from third party device"
                logger().info(f"ping is successful")

        if self.net_perf_client:
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{self.host_ip}")
            tg = sbe.traffic_generator(self.wifi_dut, self.wifi_access_point, self.wifi_client,
                                       self.net_perf_client, self.protocol, self.device_ip, self.host_ip)
            tg.run_tx()

        if self.http_server:
            self.run_http_download()

    def verify_sniffer_validation(self):
        sv = validate_sniffer_functionality(self.dut_mac_address, self.ap_bssid)
        sv.basic_verification()



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

    def stop_adv_scan(self):
        logger().info("Initiating stop scan from Remote dut")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating stop advertise from Remote device")
        self.ble_client.interfaces.bluetooth.stop_advertising()

    def run(self):
        with lock:
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


# thread for wifi scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_sniffer, wifi_dut, wifi_access_point, testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase

    def run(self):

        with lock:

            for count in range(0, 3):
                logger().info("Initiating wlan scan")
                # enables the scan in dut on channel
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                logger().info(f"scan results : {scan_results}")
                assert (len(scan_results) > 0), "scan failed"
                time.sleep(5)
            self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {self.dut_mac_address}")


    def verify_sniffer_validation(self):
        validation = True
        packet_filter2 = False

        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        logger().info(
            f"Validating Probe req(Broadcast)"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_scan_BLE_AI_20ms_C20164(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_Wifi_scan_BLE_AI_20ms_C20164"
    logger().info(f"testcase : test_Wifi_scan_BLE_AI_20ms_C20164")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=20)
    wifi_obj = ScanThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_AP_connection_BLE_AI_20ms_C20165(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_AP_connection_BLE_AI_20ms_C20165"
    logger().info("testcase : test_AP_connection_BLE_AI_20ms_C20165")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=20)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_Data_BLE_AI_20ms_C20166(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, \
                                      net_perf_client, ble_client, protocol):
    testcase = "test_Wifi_Data_BLE_AI_20ms_C20166"
    logger().info(f"testcase : test_Wifi_Data_BLE_AI_20ms_C20166")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=20)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, net_perf_client, protocol)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_scan_BLE_AI_10240ms_C20167(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_Wifi_scan_BLE_AI_10240ms_C20167"
    logger().info("testcase : test_Wifi_scan_BLE_AI_10240ms_C20167")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_adv_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=10240)
    wifi_scan_obj = ScanThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_adv_obj.start()
    wifi_scan_obj.start()
    wifi_scan_obj.wait_for_exit()
    ble_adv_obj.wait_for_exit()
    ble_adv_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_scan_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_AP_connection_BLE_AI_10240ms_C20168(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_AP_connection_BLE_AI_10240ms_C20168"
    logger().info("testcase : test_AP_connection_BLE_AI_10240ms_C20168")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=10240)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
def test_Wifi_Data_BLE_AI_10240ms_C20169(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, \
                                         net_perf_client, protocol, ble_client):
    testcase = "test_Wifi_Data_BLE_AI_10240ms_C20169"
    logger().info("testcase : test_Wifi_Data_BLE_AI_10240ms_C20169")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=10240)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, net_perf_client, protocol)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,

        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_http_dwnld_BLE_AI_20ms_C20176(wifi_sniffer, http_server, wifi_access_point, wifi_dut, \
                                            ble_client, index_path):
    testcase = "test_Wifi_http_dwnld_BLE_AI_20ms_C20176"
    logger().info("testcase : test_Wifi_http_dwnld_BLE_AI_20ms_C20176")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=20)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, http_server=http_server,
                          index_path=index_path)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_Wifi_http_dwnld_BLE_AI_10240ms_C20177(wifi_sniffer, http_server, wifi_access_point, wifi_dut, ble_client,
                                               index_path):
    testcase = "test_Wifi_http_dwnld_BLE_AI_10240ms_C20177"
    logger().info("testcase : test_Wifi_http_dwnld_BLE_AI_10240ms_C20177")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client, adv_int=10240)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, http_server=http_server,
                          index_path=index_path)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_scan_BLE_SI_10240ms_SW_5000ms_C20173(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_Wifi_scan_BLE_SI_10240ms_SW_5000ms_C20173"
    logger().info("testcase : test_Wifi_scan_BLE_SI_10240ms_SW_5000ms_C20173")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    wifi_obj = ScanThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240, ble_scan_window=5000)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_AP_conn_BLE_SI_10240ms_SW_5000ms_C20174(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_AP_conn_BLE_SI_10240ms_SW_5000ms_C20174"
    logger().info("testcase : test_AP_conn_BLE_SI_10240ms_SW_5000ms_C20174")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240, ble_scan_window=5000)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_Data_BLE_SI_10240ms_SW_5000ms_C20175(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, \
                                                   net_perf_client, protocol, ble_client):
    testcase = "test_Wifi_Data_BLE_SI_10240ms_SW_5000ms_C20175"
    logger().info("testcase : test_Wifi_Data_BLE_SI_10240ms_SW_5000ms_C20175")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240, ble_scan_window=5000)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, net_perf_client, protocol)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_http_dwnld_BLE_SI_10240ms_SW_5000ms_C20179(wifi_sniffer, http_server, wifi_access_point, wifi_dut,
                                                         ble_client, index_path):
    testcase = "test_Wifi_http_dwnld_BLE_SI_10240ms_SW_5000ms_C20179"
    logger().info("testcase : test_Wifi_http_dwnld_BLE_SI_10240ms_SW_5000ms_C20179")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240, ble_scan_window=5000)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, http_server=http_server,
                          index_path=index_path)

    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_scan_BLE_SI_5ms_SW_2point5ms_C20170(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_Wifi_scan_BLE_SI_5ms_SW_2point5ms_C20170"
    logger().info("testcase : test_Wifi_scan_BLE_SI_5ms_SW_2point5ms_C20170")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5, ble_scan_window=2.5)
    wifi_obj = ScanThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_AP_conn_BLE_SI_5ms_SW_2point5ms_C20171(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_AP_conn_BLE_SI_5ms_SW_2point5ms_C20171"
    logger().info("testcase : test_AP_conn_BLE_SI_5ms_SW_2point5ms_C20171")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5, ble_scan_window=2.5)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_Data_BLE_SI_5ms_SW_2point5ms_C20172(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, \
                                                  net_perf_client, protocol, ble_client):
    testcase = "test_Wifi_Data_BLE_SI_5ms_SW_2point5ms_C20172"
    logger().info("testcase : test_Wifi_Data_BLE_SI_5ms_SW_2point5ms_C20172")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5, ble_scan_window=2.5)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, net_perf_client, protocol)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_scan"])
def test_Wifi_http_dwnld_BLE_SI_5ms_SW_2point5ms_C20178(wifi_sniffer, http_server, wifi_access_point, wifi_dut,
                                                        ble_client, index_path):
    testcase = "test_Wifi_http_dwnld_BLE_SI_5ms_SW_2point5ms_C20178"
    logger().info("testcase : test_Wifi_http_dwnld_BLE_SI_5ms_SW_2point5ms_C20178")
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5, ble_scan_window=2.5)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, http_server=http_server,
                          index_path=index_path)
    ble_obj.start()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    ble_obj.wait_for_exit()
    ble_obj.stop_adv_scan()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


