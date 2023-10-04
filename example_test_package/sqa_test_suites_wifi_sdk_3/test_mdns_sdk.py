import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode,Si91xTCPIPFeatureBitMap,Si91xExtTCPIPFeatureBitMap, \
    RS9116CertificateType, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xPowerSaveModes, Si91xPowerSaveProcedureTypes, Si91xCustomFeatureBitMap
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping
import time

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPServer,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_mdns_neg_without_sel_feature_C19006(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections):
    capture_filename = "test_mdns_neg_without_sel_feature_C19006"

    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.mdns_init()
    assert exc_info.value.error_code == 0xFF74, "Observed wrong error code, expected is 0xFF74"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPServer | Si91xTCPIPFeatureBitMap.mDNS,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_mdns_neg_port_already_in_use_C19007(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger, sl_collections
):
    capture_filename = "test_mdns_neg_port_already_in_use_C19007"

    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    sock = wifi_dut.interfaces.wifi.open_udp_client_socket()
    assert sock == 0, "socket id received is not matched. Expected is 0"
    local_port = 5353
    wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=device_ip, server_port=local_port,
                                  timeout=15)
    data_length = 10
    data = "ABCDEFGHIJKLMNOP"
    server_ip = "192.168.10.100"
    server_port = 5001
    wifi_dut.interfaces.wifi.bsdSocketSendTo(socket_fd=sock, data=data_length, ip_addr=server_ip, port=server_port)

    wifi_dut.interfaces.wifi.mdns_init()
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.mdns_register_service()
    assert exc_info.value.error_code == 0xBB23, "Observed wrong error code, expected is  0xBB23"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.HTTPServer | Si91xTCPIPFeatureBitMap.mDNS,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_mdns_neg_multicast_socket_in_open_state_C19008(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, logger,sl_collections):
    capture_filename = "test_mdns_neg_multicast_socket_in_open_state_C19008"
    multicast_ip = "239.255.255.250"
    ip_version = 0
    result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                             retry_count=3, rejoin_parms=[0, 6, 40, 0])
    device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    logger.info(f"DUT joining to the multicast group {multicast_ip}")
    wifi_dut.interfaces.wifi.join_multicast_address(multicast_address=multicast_ip)
    wifi_dut.interfaces.wifi.mdns_init()
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.mdns_register_service()
    assert exc_info.value.error_code == 0xBB17, "Observed wrong error code, expected is  0xBB17"