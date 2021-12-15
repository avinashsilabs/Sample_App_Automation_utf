import pytest
from devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType, RS9116SecurityMode
                            )
from interfaces import wifi
from utils.logger import get_logger
from utils.time_measurer import TimeMeasurer
import time
from interfaces.wifi import SecurityMode
import interfaces.cli.rs_commands_base


def logger():
    return get_logger(__name__)

""" Author: Sirisha Ayyagari
This test plan aims to connect the WIFI AP in Enterprise mode
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Radio Server (For now running on NUC)
Step1: 1. Configuration of DUT in 2G mode
Step2 : Verifying EAP Connection in TTLS mode
Step3: Verifying EAP Connection in PEAPv0v1 mode
Step4 : Verifying EAP Connection in TLS mode
Step5 : Verifying EAP Connection by loading wrong certificate in TLS mode
Step6 : Verifying EAP Connection by loading no certificate in TLS mode
Step7 : Verifying EAP Connection by setting expired date in TLS mode

"""

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
            "band": 0,
            "ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
            "eap_cert": "wifi-user.pem"
        }
    )
]
#EAP Connection in TTLS mode

@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connectivity_with_WPA2_EAP_with_TTLS_Method(wifi_dut, wifi_access_point):
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security
          #For running in all modes if all these modes supported in Raspi
    #eap_method_dict = {'TLS':1,'TTLS':2,'PEAPv0':3,'PEAPv1':4}

    with TimeMeasurer() as t:

          # enable Roaming
            wifi_dut.interfaces.wifi.set_roaming(roam_threshold=60, roam_hysterisis=4)
            # test_scan
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="test_ap")
            logger().info(scan_results)
            # enable rejoin
            wifi_dut.interfaces.wifi.rejoin()
            # test_wifi_join
            wifi_dut.interfaces.wifi.eap_method(eap_method="TTLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
            result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
            # assert result
            # Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Initiating power save
            wifi_dut.interfaces.wifi.power_save(2)
            wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(2)


# EAP Connection in PEAPv0v1 mode
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connectivity_with_WPA2_EAP_with_PEAPv0_v1_Method(wifi_dut, wifi_access_point):
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    with TimeMeasurer() as t:
            # enable Roaming
            wifi_dut.interfaces.wifi.set_roaming(roam_threshold=60, roam_hysterisis=4)
            # test_scan
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="test_ap")
            logger().info(scan_results)
            # enable rejoin
            wifi_dut.interfaces.wifi.rejoin()
            # test_wifi_join
            wifi_dut.interfaces.wifi.eap_method(eap_method="peap", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
            result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
            # Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Initiating power save
            wifi_dut.interfaces.wifi.power_save(2)
            wifi_dut.interfaces.wifi.bt_power_save(2)


 #EAP Connection in TLS mode
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connectivity_with_WPA2_EAP_with_TLS_Method(wifi_dut, wifi_access_point):
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    with TimeMeasurer() as t:
          # enable Roaming
            wifi_dut.interfaces.wifi.set_roaming(roam_threshold=60, roam_hysterisis=4)
            # test_scan
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="test_ap")
            logger().info(scan_results)
            # enable rejoin
            wifi_dut.interfaces.wifi.rejoin()
            # test_wifi_join
            wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
            result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
            # Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Initiating power save
            wifi_dut.interfaces.wifi.power_save(2)
            wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(2)



pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
            "band": 0,
            "ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
              # Load wrong certificate
            "eap_cert": "ca-chain.cert.pem"
        }
    )
]


# EAP Connection in TTS mode with wrong certificate
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connectivity_with_WPA2_EAP_with_wrongcertificate_TLS(wifi_dut, wifi_access_point):
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    with TimeMeasurer() as t:
          # enable Roaming
            wifi_dut.interfaces.wifi.set_roaming(roam_threshold=60, roam_hysterisis=4)
            # test_scan
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="test_ap")
            logger().info(scan_results)
            # enable rejoin
            wifi_dut.interfaces.wifi.rejoin()
            # test_wifi_join
            wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
            assert exc_info.value.error_code == 0x45
            # Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Initiating power save
            wifi_dut.interfaces.wifi.power_save(2)
            wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(2)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
            "band": 0,

        }
    )
]

# EAP Connection in TTS mode with no certificate
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connectivity_with_WPA2_EAP_with_nocertificate_TLS(wifi_dut, wifi_access_point):
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    with TimeMeasurer() as t:
          # enable Roaming
            wifi_dut.interfaces.wifi.set_roaming(roam_threshold=60, roam_hysterisis=4)
            # test_scan
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="test_ap")
            logger().info(scan_results)
            # enable rejoin
            wifi_dut.interfaces.wifi.rejoin()
           # test_wifi_join
            wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
            assert exc_info.value.error_code == 0x45
            #Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Initiating power save
            wifi_dut.interfaces.wifi.power_save(2)
            wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(2)

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 2,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.Default | RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
            "band": 0,
            "ext_tcpip_features": RS9116CertificateType.EAPClientCertificate,
              #expired date in certificate
            "eap_cert": "ca-chain.cert.pem"
        }
    )
]

# # EAP Connection in TTS mode with expired date certificate
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connectivity_with_WPA2_EAP_with_expireddate_TLS(wifi_dut, wifi_access_point):
    ap_user_name = "\\\"user1\\\""
    ap_password = "\\\"12345678\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

    with TimeMeasurer() as t:
          # enable Roaming
            wifi_dut.interfaces.wifi.set_roaming(roam_threshold=60, roam_hysterisis=4)
            # test_scan
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid="test_ap")
            logger().info(scan_results)
            # enable rejoin
            wifi_dut.interfaces.wifi.rejoin()
            # test_wifi_join
            wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"", private_key="\"\"")
        with pytest.raises(WlanError) as exc_info:
            result = wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)
            assert exc_info.value.error_code == 0x45
            # Get IP through DHCP
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(
                result, wifi_dut.interfaces.wifi.IPConfig
            ), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            # Initiating power save
            wifi_dut.interfaces.wifi.power_save(2)
            wifi_dut.interfaces.wifi.bt_power_save(2)
            time.sleep(2)