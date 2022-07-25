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
                 wifi_access_point=None,eap_type = "TLS", testcase=None, wifi_client=None, \
                 net_perf_client=None, protocol=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.eap_type = eap_type
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client

    def run(self):

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
        # test_scan
        scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
        logger().info(scan_results)

        logger().info("enable rejoin")
        self.wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        # test_wifi_join
        self.wifi_dut.interfaces.wifi.eap_method(eap_method=self.eap_type, eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
        result = self.wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
        # Get IP through DHCP
        result = self.wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info(f"Found device ip :{device_ip}")

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
        status = ping(device_ip, ping_count)
        assert status == True, "DUT is not responding to ping request from third party device before store configuration"
        logger().info("ping is successful")

        logger().info("Initiating disconnect from DUT")
        # Wlan Disconnect
        self.wifi_dut.interfaces.wifi.leave()
        time.sleep(10)

    def verify_sniffer_validation(self):

        validation = True

        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter2 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"

        # Validating the EAP failure frames
        packet_filter3 = f"wlan.addr=={self.dut_mac_address} && eap|| eapol"

        packet_filter4 = f"wlan.addr=={self.ap_bssid} && eap || eapol"

        packet_filter5 = f'wlan.ta == {self.dut_mac_address} and wlan.ra == {self.ap_bssid} and ' \
                         f'wlan.fc.pwrmgt == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

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

        logger().info(
            f"Validating EAP frames in sniffer"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find EAP frames sent from STA in sniffer '
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find EAP frames sent from AP in sniffer '

        logger().info(f"Validating QOS  NULL data frames with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find power management bit in QOS null frames in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

        logger().info("Successfully validated sniffer packets")

# this thread used for sta+ble as a slave
class BleThread_Advertise(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        # Set up DUT for BLE advertising
        logger().info("Initialising BLE")
        self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.bt_dut_address is not None, "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.bt_dut_address}")
        time.sleep(5)

    def run(self):

        logger().info(f"Advertising the DUT")
        self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=30)
        logger().info("Initiating scan from Remote device")
        # Begin Scanning for BLE devices
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
        assert bt_client_address is not None, "Unable to fetch bluetooth address from Remote device"
        logger().info(f"Started scan from remote BLE device")
        logger().info("\n***********{}**********\n".format(bt_client_address))
        for i in range(0, 5):
            time.sleep(10)
            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info("\n***scan results:{}**********\n".format(found_devices))

        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"
        logger().info(f"*****Logic Analyzer validation is pending*******")

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
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",\
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_TLS_BLE_adv_C20215(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_TLS_BLE_adv_C20215"
    logger().info("testcase : test_sta_ble_TLS_BLE_adv_C20215")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, eap_type="TLS", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()





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
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",\
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_TTLS_BLE_adv_C20216(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_TTLS_BLE_adv_C20216"
    logger().info("testcase : test_sta_ble_TTLS_BLE_adv_C20216")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, eap_type="TTLS", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()


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
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable",\
                                         "disassociated", "ble_stop_adv", "clear_certs"])
def test_sta_ble_PEAP_BLE_adv_C20217(wifi_sniffer, wifi_access_point, wifi_dut, ble_client):
    testcase = "test_sta_ble_PEAP_BLE_adv_C20217"
    logger().info("testcase : test_sta_ble_PEAP_BLE_adv_C20217")
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_obj = BleThread_Advertise(wifi_dut, ble_client)
    wifi_obj = WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, eap_type="PEAP", testcase=testcase)
    ble_obj.start()
    wifi_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.wait_for_exit()
    logger().info("Initiating stop scan from Remote device")
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.verify_sniffer_validation()
