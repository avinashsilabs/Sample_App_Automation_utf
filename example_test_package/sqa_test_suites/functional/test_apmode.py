import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap,RS9116CoexMode)
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict

"""Test Author = Rakesh Nayini

        1. Start the sniffer before connection
        2. Required A7 EVK(DUT) board 
        3. Stop the sniffer
        4. Initiate ping from the dut
        5. Analyizing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""

# Configuring static IP to DUT
mode = 'static'
ip_address = '192.168.100.76'
subnet = '255.255.255.0'
gateway = '192.168.100.76'


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_C19454(wifi_sniffer, wifi_dut, wifi_client, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19454')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    assert (wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip)), \
        "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    packet_filter1 = f'((wlan.country_info.code == "US")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find beacon frame with Region US in Sniffer"
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "EU ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_C19455(wifi_sniffer, wifi_dut, wifi_client, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19455')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    assert (wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip)), \
        "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    packet_filter1 = f'((wlan.country_info.code == "EU")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find beacon frame with Region EU in Sniffer"
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "JP ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_C19456(wifi_sniffer, wifi_dut, wifi_client, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19456')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    assert (wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip)), \
        "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    packet_filter1 = f'((wlan.country_info.code == "JP")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find beacon frame with Region JP in Sniffer"
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [36, 40, 48, 149, 165])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_C19434(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, channel, protocol):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19434')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {device_ip}")
    logger().info(f"******** Host IP ******** {host_ip}")
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), "Client filed to ping AP"
    logger().info('********** preparing iperf **********')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    logger().info('********** creating results object for sharing between host and dut **********')
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info('********** open socket and start listening **********')
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info('********** start iperf **********')
        net_perf_client.interfaces.net_perf.start()
        logger().info('********** capture device output **********')
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    logger().info('********** get and print throughput **********')
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )
    time.sleep(5)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("dtim", [1, 2, 3, 6, 10])
@pytest.mark.parametrize("channel", [11])
def test_C19444(wifi_sniffer, wifi_dut, wifi_client, dtim, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19444')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ap(dtim_period=dtim, channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    assert (wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip)), \
        "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"]
    time.sleep(5)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("beacon", [100, 200, 600, 1000])
@pytest.mark.parametrize("channel", [11])
def test_C19443(wifi_sniffer, wifi_dut, wifi_client, beacon, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19443')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(5)
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    time.sleep(10)
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    assert (wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip)), \
        "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    logger().info('********** Validate Beacon frame **********')
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008)'
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"]
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)["packet_count"]
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "beacon": 100,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_C19435(wifi_sniffer, wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    with pytest.raises(AssertionError) as exc_info:
        logger().info(" ********** DUT works as a Ap mode ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=10)
    assert "Device must be initialized for the correct band" in str(exc_info)
    logger().info("Device must be initialized for the correct band")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19432(wifi_sniffer, wifi_dut, wifi_clients, channel):
    logger().info(f'************* Configuring Static IP *************')
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    time.sleep(5)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19432')
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_dut.interfaces.wifi.start_ap()
    for iteration in range(2):
        for i in range(0, len(wifi_clients)):
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(0.5)
            logger().info(f'{wifi_clients[i]}')
            logger().info(f'Station :{i}')
            assert (wifi_clients[i].interfaces.wifi.ping(
                server_ip=wifi_clients[i].interfaces.wifi.client_gateway_ip)), "Client failed to ping DUT"
            device_ip = wifi_clients.interfaces.wifi.client_gateway_ip
            logger().info(f"********* Dut IP **********: {device_ip}")
            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {mac_address}")
            wifi_clients[i].interfaces.wifi.leave()
            logger().info(f'Station :{i} Disconnecting with AP')
            time.sleep(10)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )
    time.sleep(5)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "12345678",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_C19430_C19442(wifi_sniffer, wifi_dut, wifi_clients, channel):
    logger().info(f'************* Configuring Static IP *************')
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    time.sleep(5)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19430_C19442')
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_dut.interfaces.wifi.start_ap()
    for iteration in range(2):
        for i in range(0, len(wifi_clients)):
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(0.5)
            logger().info(f'{wifi_clients[i]}')
            logger().info(f'Station :{i}')
            assert (wifi_clients[i].interfaces.wifi.ping(
                server_ip=wifi_clients[i].interfaces.wifi.client_gateway_ip)), "Client failed to ping DUT"
            device_ip = wifi_clients.interfaces.wifi.client_gateway_ip
            logger().info(f"********* Dut IP **********: {device_ip}")
            time.sleep(5)
            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {mac_address}")
            time.sleep(10)
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet "
        "in sniffer"
    )
    time.sleep(5)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.HTTPServerRootPathBypass,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
def test_C19436(wifi_sniffer, wifi_dut, wifi_client, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19436')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    assert (wifi_client.interfaces.wifi.ping(server_ip=wifi_client.interfaces.wifi.client_gateway_ip)),\
        "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_client.interfaces.wifi.leave()
    logger().info('********** Validate Beacon frame **********')
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"]
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "features": RS9116FeatureBitMap.Aggregation,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "dtim": 4, "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [36])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_C19447_Tx(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19447_Tx")
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {device_ip}")
    logger().info(f"******** Host IP ******** {host_ip}")
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), "Client filed to ping AP"
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    logger().info(f"********* Dut IP **********: {device_ip}")
    # starting iperf
    logger().info("***** starting iperf *****")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()
    # open socket and send traffic
    logger().info("***** open socket and send traffic *****")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    # get and print throughput
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info("***** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol *****")
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan_radio.channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ["packet_count"]
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "features": RS9116FeatureBitMap.Aggregation,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "dtim": 4, "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [36])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_C19447_Rx(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19447_Rx")
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** DUT works as a Ap mode ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {device_ip}")
    logger().info(f"******** Host IP ******** {host_ip}")
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), "Client filed to ping AP"
    # preparing iperf
    logger().info("***** preparing iperf *****")
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
    # creating results object for sharing between host and dut
    logger().info("***** creating results object for sharing between host and dut *****")
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    # open socket and start listening
    logger().info("***** open socket and start listening *****")
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=device_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        # start iperf
        logger().info("***** start iperf *****")
        net_perf_client.interfaces.net_perf.start()
        # capture device output
        logger().info("***** capture device output *****")
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    # get and print throughput
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None
    __print_throughput(tp)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info("***** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol *****")
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan_radio.channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ["packet_count"]
    time.sleep(2)
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "features": RS9116FeatureBitMap.Aggregation,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "EU ", "channel": 149,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_C19458(wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    with pytest.raises(AssertionError) as exc_info:
        logger().info(" ********** DUT works as a Ap mode ********* ")
        wifi_dut.interfaces.wifi.start_ap()
    assert "Device must be initialized for the correct band" in str(exc_info)
    logger().info("Device must be initialized for the correct band")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "features": RS9116FeatureBitMap.Aggregation,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "JP ", "channel": 149,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_C19457(wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ip(mode=mode, ip_address=ip_address, subnet=subnet, gateway=gateway)
    logger().info("********* configuring static ip to DUT *********")
    with pytest.raises(AssertionError) as exc_info:
        logger().info(" ********** DUT works as a Ap mode ********* ")
        wifi_dut.interfaces.wifi.start_ap()
    assert "Device must be initialized for the correct band" in str(exc_info)
    logger().info("Device must be initialized for the correct band")
    wifi_dut.interfaces.wifi.leave()


