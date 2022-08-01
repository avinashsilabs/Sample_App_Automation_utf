import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                            RS9116CustomFeatureBitMap,
                            RS9116ConfigFeatureBitMap,
                            RS9116TCPIPFeatureBitMap,
                            RS9116ExtCustomFeatureBitMap,
                            RS9116ExtTCPIPFeatureBitMap,
                            RS9116CertificateType,
                            RS9116SecurityMode, RS9116PowerSaveProcedureTypes,RS9116JoinFeatureBitMap
                            )

def logger():
    return get_logger(__name__)

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
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})

 #EAP Connection in TLS mode
def test_radius_server_connectivity_in_WPA2_EAP(wifi_dut, wifi_access_point, radius_server):
    ap_user_name = "\\\"user1\\\""
    ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
    dut_ssid = wifi_access_point.interfaces.wifi.ssid
    dut_security = wifi_access_point.interfaces.wifi.security

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
