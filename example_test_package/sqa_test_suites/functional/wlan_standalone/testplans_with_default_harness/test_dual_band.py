import pytest
import time
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.socket import SOCKET_TYPE_TCP
import string
import random
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf_wiseconnect.devices.rs911x import RS9116PowerSaveModes
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect.devices.rs911x import (
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116Band,
    RS9116RegionCode,
)


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'ABC_Europe',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 12,
            'region': 'Europe',

        },
        1: {
            'ssid': 'ABC_US',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 6,
            'region': 'US',
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default,
        "set_send_feature_frame": True,
        "band": RS9116Band.DualBand,
        "region_code": RS9116RegionCode.US,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_dual_band_scan_with_US_regions_c19011(wifi_access_points, wifi_dut):
    logger().info("DUT region is set to US")
    channel_list = [12, 13, 14]
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    for iteration in range(0, len(wifi_access_points)):
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(3)
        logger().info(f"***********SCAN RESULT for access point:************{scan_results}")
        assert (len(scan_results) >= 1), 'unable to scan the results'
        for count in scan_results:
            logger().info(f"rf_channel : {count.rf_channel} ssid: {count.ssid}")
            assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
        logger().info(f" channels which are not supported in US region are :{channel_list}")
        logger().info(
            f"DUT is scanned only supported channels in US region and channels which are in channel list are not there in scan results hence test case passed ")


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'ABC_Europe',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 60,
            'region': 'Europe',

        },
        1: {
            'ssid': 'ABC_US',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 149,
            'region': 'US',
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default,
        "set_send_feature_frame": True,
        "band": RS9116Band.DualBand,
        "region_code": RS9116RegionCode.Europe,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_dual_band_scan_with_EU_regions_c19012(wifi_access_points, wifi_dut):
    # Enables the wifi power save in DUT
    channel_list = [14, 149, 151, 157, 161, 165]
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # Enables the bt power save in DUT
    # wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
    logger().info("DUT region is set to Europe")
    for iteration in range(0, len(wifi_access_points)):
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(3)
        logger().info(f"***********SCAN RESULT for access point:************{scan_results}")
        assert (len(scan_results) >= 1), 'unable to scan the results'
        for count in scan_results:
            logger().info(f"rf_channel : {count.rf_channel} ssid: {count.ssid}")
            assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
        logger().info(f" channels which are not supported in US region are :{channel_list}")
        logger().info(
            f"DUT is scanned only supported channels in Europe region and channels which are in channel list are not there in scan results hence test case passed ")


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'ABC_US',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 153,
            'region': 'US',

        },
        1: {
            'ssid': 'ABC_Japan',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 44,
            'region': 'Japan',
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default,
        "set_send_feature_frame": True,
        "band": RS9116Band.DualBand,
        "region_code": RS9116RegionCode.Japan,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_dual_band_scan_with_JP_regions_c19013(wifi_access_points, wifi_dut):
    channel_list = [149, 153, 157, 161, 165]
    # Enables the wifi power save in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

    logger().info("DUT region is set to Japan")
    for iteration in range(0, len(wifi_access_points)):
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(3)
        logger().info(f"***********SCAN RESULT for access point:************{scan_results}")
        assert (len(scan_results) >= 1), 'unable to scan the results'
        for count in scan_results:
            logger().info(f"rf_channel : {count.rf_channel} ssid: {count.ssid}")
            assert (count.rf_channel not in channel_list), f"Scan should not happen in channels {channel_list}"
        logger().info(f" channels which are not supported in US region are :{channel_list}")
        logger().info(
            f"DUT is scanned only supported channels in Japan region and channels which are in channel list are not there in scan results hence test case passed ")


@pytest.mark.config(
    "wifi_access_points",
    wifi={
        0: {
            'ssid': 'ABC_US',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 149,
            'region': 'US',

        },
        1: {
            'ssid': 'ABC_Japan',
            'security': 'WPA2',
            'passphrase': '12345678',
            'channel': 13,
            'region': 'Japan',
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default,
        "set_send_feature_frame": True,
        "band": RS9116Band.DualBand,
        "region_code": RS9116RegionCode.Worldwide,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_dual_band_scan_with_World_regions_c19014(wifi_access_points, wifi_dut):

    # Enables the wifi power save in DU
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)


    logger().info("DUT region is set to World region")
    for iteration in range(0, len(wifi_access_points)):
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        time.sleep(3)
        logger().info(f"***********SCAN RESULT for access point:************{scan_results}")
        assert (len(scan_results) >= 1), 'unable to scan the results'
        for count in scan_results:
            logger().info(f"rf_channel : {count.rf_channel} ssid: {count.ssid}")

ping_count = 10

@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'ABC',
        'security': 'WPA2',
        'passphrase': '12345678',
        'channel': 1
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.Default,
        "set_send_feature_frame": True,
        "band": RS9116Band.DualBand,
        "region_code": RS9116RegionCode.Worldwide,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
    }
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dual_band_connection_with_country_IE_Mismatch_C19010(wifi_access_point, wifi_dut, remote_socket_factory):
    sock_port = 5001
    scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    logger().info(scan_results)
    assert (len(scan_results) >= 1), 'unable to scan the results'
    result = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    #
    # This API Enables the DHCP in DUT
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f" ********* enabling enhance max psp in our DUT*******")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    # Initiate ping from third party wifi-client to DUT
    ping(device_ip, ping_count)

    #tcp data transfer to be done yet
    server_socket = remote_socket_factory.interfaces.socket.create_socket()
    server_socket.time_limit = 3600
    status = server_socket.start_server(port=sock_port, socket_type=SOCKET_TYPE_TCP)
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    assert sock == 0, f"socket id received is wrong, expected is 0"
    logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
    wifi_dut.interfaces.wifi.bind(sock, device_ip, sock_port)
    wifi_dut.interfaces.wifi.connect_to_server(sock, server_socket, server_port=sock_port)

    data_size = 100
    iter = 100

    for i in range(0, iter):
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        wifi_dut.interfaces.wifi.send_data(sock, data_size, data=data_sent)
        data = remote_socket_factory.interfaces.socket.sockets[0].recv_data_tcp(data_size)
        assert len(data) == data_size
    wifi_dut.interfaces.wifi.close_socket(0)

    wifi_dut.interfaces.wifi.leave()
