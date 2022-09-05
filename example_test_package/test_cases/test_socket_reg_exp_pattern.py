import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap
)
import re

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"]
)
def test_socket_command_with_regular_expression(
    wifi_dut, wifi_access_point, ssl_client, logger
):
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()

    wifi_dut.interfaces.wifi.clear_certificate(
        RS9116CertificateType.SSLServerCertificate, cert_index=0
    )
    wifi_dut.interfaces.wifi.clear_certificate(
        RS9116CertificateType.SSLServerPrivateKey, cert_index=0
    )

    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode("utf-8")

    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=1)
    assert sock == 0, f"socket id received is wrong, expected is 0"

    wifi_dut.interfaces.wifi.bind(sock, device_ip, 5002)
    wifi_dut.interfaces.wifi.listen(sock, backlog=1)

    ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5002)

    # Example: 1. Search with status and error code then pattern is "status: 0x([0-9a-fA-F]+)"
    # 2. Search for either success or Error code 0xFFFFFFFF then pattern is "/success | 0xFFFFFFFF/"
    result = wifi_dut.interfaces.wifi.accept(
        socket_id=sock, expected=re.compile(r"success | 0xFFFFFFFF"), timeout=120
    )
    assert "0xFFFFFFFF" in str(
        result
    ), "DUT sent wrong error code, expected is 0xFFFFFFFF"
