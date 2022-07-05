import pytest
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType, RS9116SecurityMode, RS9116PowerSaveProcedureTypes
                            )
from utf.interfaces import wifi
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
import time
from utf.interfaces.wifi import SecurityMode, WlanError
import utf_wiseconnect.interfaces.cli.rs_commands_base
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf.interfaces.cli import CLITransportException



ping_count = 10
iter_count = 5

def logger():
    return get_logger(__name__)

""" 
This test plan aims to connect the WIFI AP in Enterprise mode
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Radio Server (For now running on NUC)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Verifying EAP Connection in TTLS mode
Step3: Verifying EAP Connection in PEAPv0 mode
Step4 : Verifying EAP Connection in TLS mode
Step5 : Verifying EAP Connection by loading wrong certificate in TLS mode
Step6 : Verifying EAP Connection by loading no certificate in TLS mode
Step7 : Verifying EAP Connection by setting expired date in TLS mode

Author: swathi.pathuri
"""


class sniffer_validation_process:

    def __init__(self, wifi_sniffer = None, wifi_dut = None, wifi_access_point = None, dut_mac_address=None ,\
                 ap_bssid = None, conn_status = True):

        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.dut_mac_address = dut_mac_address
        self.ap_bssid = ap_bssid
        self.conn_status = conn_status

    def verify_sniffer_validation(self):

        validation = True


        beacon_filter = f"(wlan.fc.type_subtype == 0x0008) and (wlan.sa == {self.ap_bssid} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter2 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter3 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"

        packet_filter4 = f" (dhcp) && (wlan.addr == {self.ap_bssid}) && (wlan.addr == {self.dut_mac_address})"

        packet_filter5 = f'wlan.sa == {self.dut_mac_address} and ' \
                         f'wlan.fc.pwrmgt == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter6 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        # Validating the de auth frames
        packet_filter7 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x000c'

        # Validating the EAP failure frames
        packet_filter8 = f'wlan.sa == {self.ap_bssid} and wlan.da == {self.dut_mac_address} and eap.code == 4'


        logger().info(
            f"Validating beacons"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, beacon_filter)[
            'packet_count'], 'Unable to find beacons in sniffer'

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

        if not self.conn_status:

            logger().info(
                f"Validating EAP failure frame in sniffer"
            )
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter8)[
                'packet_count'], 'Unable to find EAP faliure frames sent from AP in sniffer '


        if self.conn_status:

            logger().info(f"Validating QOS  NULL data frames with power management bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
                'packet_count'], 'Unable to find power management bit in QOS null frames in sniffer capture'

            logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
                'packet_count'], 'Unable to find ps polls in sniffer capture'

            logger().info(f"Validating deauth frames are sent from the device")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter7)[
                'packet_count'], 'Unable to find de-auths in sniffer capture'
            logger().info("Successfully validated sniffer packets")





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
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_in_WPA2_EAP_TLS_C19018(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_C19018"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
    logger().info(scan_results)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    # test_wifi_join
    wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
    result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
    # Get IP through DHCP
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"Found device ip :{device_ip}")

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating powersave")
    # Initiating power save
    # This API Enables the wifi power save mode in DUT

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    # # Enables the bt power save in DUT

    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
    time.sleep(2)

    logger().info("Initiating ping")
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status == True, "DUT is not responding to ping request from third party device before store configuration"
    logger().info("ping is successful")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = sniffer_validation_process(wifi_sniffer,wifi_dut,wifi_access_point, dut_mac_address, ap_bssid)
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
        #"ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TTLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_in_WPA2_EAP_TTLS_C19019(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TTLS_C19019"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
    logger().info(scan_results)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    # test_wifi_join
    wifi_dut.interfaces.wifi.eap_method(eap_method="TTLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
    result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
    # Get IP through DHCP
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating power save")
    # This API Enables the wifi power save mode in DUT

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    # # Enables the bt power save in DUT

    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("Initiating ping")
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status == True, "DUT is not responding to ping request from third party device before store configuration"
    logger().info("ping is successful")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
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
        #"ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
        #"eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_in_WPA2_EAP_PEAPv0_C19020(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_PEAPv0_C19020"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
    logger().info(scan_results)

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    # test_wifi_join
    wifi_dut.interfaces.wifi.eap_method(eap_method="PEAP", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
    result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
    # Get IP through DHCP
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("Initiating power save")
    # This API Enables the wifi power save mode in DUT

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
    # # Enables the bt power save in DUT

    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("Initiating ping")
    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status == True, "DUT is not responding to ping request from third party device before store configuration"
    logger().info("ping is successful")

    logger().info("Initiating disconnect from DUT")
    # Wlan Disconnect
    wifi_dut.interfaces.wifi.leave()
    time.sleep(10)

    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid)
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
        # "ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
        # "eap_cert": "wifi-user.pem"
    }
)
 #EAP Connection in TLS mode
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C19022(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_when_no_cert_C19022"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
    logger().info(scan_results)
    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("enable eap method")
    # test_wifi_join
    wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")

    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"

    logger().info("Connection failed when no certs loaded")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,conn_status=False)
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)

@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
# EAP Connection in TTS mode with no certificate
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_with_WPA2_EAP_with_expired_cert_TLS_C19023(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_connectivity_with_WPA2_EAP_with_expired_cert_TLS_C19023"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    wifi_dut.interfaces.wifi.set_rtc(seconds=50, minutes=59, hour=23,
                                     month_day=1,
                                     month=1, year=1930, week_day=4)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("enable eap method")
    # test_wifi_join
    wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")

    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"

    logger().info("Connection failed when no certs loaded")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
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
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode
        | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    }
)

@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
# EAP Connection in TTS mode with no certificate
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_with_WPA2_EAP_with_valid_and_expired_cert_TLS_C19025(wifi_sniffer, wifi_dut, wifi_access_point):

    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    for i in range(0,2):

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

        logger().info("Setting roam parameters")
        # enable Roaming
        wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

        logger().info("scanning for AP")
        # test_scan
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
        logger().info(scan_results)

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")

        logger().info("enable rejoin")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("enable eap method")
        # test_wifi_join
        wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
        logger().info("Initiate connection")

        if i == 0:
            with pytest.raises(WlanError) as exc_info:
                wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
                assert exc_info.value.error_code == 0x8, "Connection should fail when expired certs loaded"
                logger().info("stopping capture")
                wifi_sniffer.interfaces.capture.stop_capture()

                verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
                                                            ap_bssid, conn_status=False)
                verify_sniffer.verify_sniffer_validation()
        else:
            wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)

            # Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            logger().info("Initiating power save")
            # This API Enables the wifi power save mode in DUT

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                     RS9116PowerSaveProcedureTypes.FastPowerSave)
            # # Enables the bt power save in DUT

            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("Initiating ping")
            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status == True, "DUT is not responding to ping request from third party device before store configuration"
            logger().info("ping is successful")

            logger().info("Initiating disconnect from DUT")
            # Wlan Disconnect
            wifi_dut.interfaces.wifi.leave()
            time.sleep(10)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address,
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
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
        | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
        | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
        | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
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
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_connectivity_in_WPA2_EAP_TLS_when_wrong_cert_C19024(wifi_sniffer, wifi_dut, wifi_access_point):
    testcase = "test_connectivity_in_WPA2_EAP_TLS_when_wrong_cert_C19024"
    validation = True
    logger().info("configuring the Sniffer with the channel")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info("start capturing with Sniffer by giving the test case name as filename")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)

    logger().info("Setting roam parameters")
    # enable Roaming
    wifi_dut.interfaces.wifi.set_roaming(roaming_threshold=60, roaming_hysterisis=4)

    logger().info("scanning for AP")
    # test_scan
    scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
    logger().info(scan_results)

    logger().info("Getting the DUT mac")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {ap_bssid}")

    logger().info("enable rejoin")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    logger().info("enable eap method")
    # test_wifi_join
    wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")

    logger().info("Initiate connection")
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
        assert exc_info.value.error_code == 0x8, "Connection should fail when no certs loaded"

    logger().info("Connection failed when no certs loaded")
    logger().info("stopping capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    verify_sniffer = sniffer_validation_process(wifi_sniffer, wifi_dut, wifi_access_point, dut_mac_address, ap_bssid,
                                                conn_status=False)
    verify_sniffer.verify_sniffer_validation()
