import pytest
import time
from retry import retry
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap, RS9116CoexMode)
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch

"""Test Author = Rakesh Nayini
    Reworked by CG, Rashmi & Team.

        1. DUT in AP Mode
        2. Required A7 EVK(DUT) board     
        3. Start the sniffer before connection
        4. Stop the sniffer
        5. Initiate ping from the dut
        6. Analyizing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
"""


def logger():
    return get_logger(__name__)



def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'


def run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol, iperf_time=60):
    ping_count = 5
    for count in range(3):
        try:
            logger().info("***** preparing iperf dut as client *****")
            net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=protocol,
                                                            time_out=iperf_time)
            logger().info("Verifying host connection")
            ping_from_client(dut_ip, ping_count)
            net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** open socket and send traffic *****")
            wifi_dut.interfaces.wifi.send_traffic_from_device(
                host_ip,
                dut_ip,
                net_perf_client.interfaces.net_perf.server_port,
                net_perf_client.interfaces.net_perf.protocol,
                net_perf_client.interfaces.net_perf.client_options,
            )
            logger().info("***** Adding 5 sec sleep before printing throughput *****")
            time.sleep(5)
            logger().info("***** get and print throughput *****")
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, 'Unable to retrieve the Throughput information'
            __print_throughput(tp)
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)
            break
        except:
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)


def run_iperf_dut_as_server(wifi_dut, net_perf_client, host_ip, dut_ip, protocol, iperf_time=60):
    ping_count = 5
    for count in range(3):
        try:
            logger().info(f"***** preparing iperf dut as server *****")
            net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol,
                                                            time_out=iperf_time)
            time.sleep(3)
            logger().info("***** creating results object for sharing between host and dut *****")
            result = Result(net_perf_client.interfaces.net_perf.protocol)
            time.sleep(3)
            logger().info("Verifying host connection")
            ping_from_client(dut_ip, ping_count)
            logger().info("***** open socket and start listening *****")
            with wifi_dut.interfaces.wifi.start_socket_reader(
                    log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                    result=result,
                    protocol=net_perf_client.interfaces.net_perf.protocol,
                    port=net_perf_client.interfaces.net_perf.client_port,
                    device_ip=dut_ip,
                    data_len=net_perf_client.interfaces.net_perf.client_data_len,
                    time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
                logger().info("***** start iperf *****")
                net_perf_client.interfaces.net_perf.start()
                logger().info("***** capture device output *****")
                wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
            logger().info("***** Adding 5 sec sleep before printing throughput *****")
            time.sleep(5)
            logger().info("***** get and print throughput *****")
            tp = net_perf_client.interfaces.net_perf.process_output(result)
            assert tp is not None, 'Unable to retrieve Throughput '
            __print_throughput(tp)
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)
            break
        except:
            net_perf_client.interfaces.net_perf.close_files()
            net_perf_client.interfaces.net_perf.iperf_process.stop(5)


@retry(Exception, delay=10, tries=3)
def client_join(wifi_client, ssid="RS9116_AP"):
    logger().info(f"wifi_client is: {wifi_client.name}")
    wifi_client.interfaces.wifi.join(ssid=ssid)


@retry(Exception, delay=10, tries=4)
def ping_from_client(dut_ip, ping_count):
    status = ping(dut_ip, ping_count)
    assert status, "Failed to ping DUT...RASPI-STA is disconnected from DUT-AP"


@pytest.fixture()
def teardown(wifi_dut):
    yield
    try:
        logger().info("Cleaning up the DUT")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.wireless_deinit()
        logger().info("Closing all opened sockets in DUT")
        wifi_dut.interfaces.wifi.close_sockets()
        time.sleep(3)
    except:
        logger().info("Recovering the DUT")
        wifi_dut.interfaces.wifi.reset()


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "server_socket_limit": 5,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_UDP_Rx_data_C19465(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Rx_data_C19465')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating UDP RX traffic *****")
        run_iperf_dut_as_server(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008)  or' \
                         f'(wlan.fc.type_subtype == 0x0000) or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "server_socket_limit": 5,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_TCP_Rx_data_C19464(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Rx_data_C19464')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating TCP RX traffic *****")
        run_iperf_dut_as_server(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008) or' \
                         f'(wlan.fc.type_subtype == 0x0000)  or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_TCP_Tx_data_C19462(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Tx_C19462')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating TCP TX traffic from DUT *****")
        run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008) or' \
                         f'(wlan.fc.type_subtype == 0x0000)  or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Validate_UDP_Tx_data_C19463(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel,
                                           utf_constants, teardown):
    validation = True
    iter_count = utf_constants.get('iter_count')
    ping_count = utf_constants.get('ping_count')
    dut_mac_address = None
    for count in range(iter_count):
        logger().info(f"Initiating test for iteration: {count + 1}")
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Tx_C19463')
        time.sleep(3)

        ip_dict = wifi_dut.interfaces.wifi.ip
        if not ip_dict:
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                             static_subnet=static_subnet,
                                                             static_gateway=static_gateway)
            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            time.sleep(10)
        logger().info(" ********** Started DUT as an AP ********* ")

        logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
        client_join(wifi_client, ssid="RS9116_AP")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {dut_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")

        logger().info("***** Pinging to DUT from wifi_client  *****")
        ping_from_client(dut_ip, ping_count)
        logger().info("***** Ping successful *****")
        time.sleep(5)

        if not dut_mac_address:
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

        logger().info("***** Initiating UDP TX traffic from DUT *****")
        run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"*********Validating the beacon frame in sniffer **********")
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], "not found beacon from DUT"
        logger().info("********* Beacon found from DUT********")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                         f'!(wlan.fc.type_subtype == 0x0008)  or' \
                         f'(wlan.fc.type_subtype == 0x0000) or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

        logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
        wifi_client.interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Iteration '{count + 1}' completed")


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_TCPSocket_Create_Transfer_Terminate_30min_C19480(wifi_sniffer, net_perf_client, wifi_dut, wifi_client,
                                                                protocol, channel, utf_constants, teardown):
    validation = True
    test_run_time = utf_constants.get('time_duration')
    ping_count = utf_constants.get('ping_count')
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_Tx_30min_C19480')
    time.sleep(3)

    ip_dict = wifi_dut.interfaces.wifi.ip
    if not ip_dict:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                         static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(10)
    logger().info(" ********** Started DUT as an AP ********* ")

    logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
    client_join(wifi_client, ssid="RS9116_AP")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {dut_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")

    logger().info("***** Pinging to DUT from wifi_client  *****")
    ping_from_client(dut_ip, ping_count)
    logger().info("***** Ping successful *****")
    time.sleep(5)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

    sw = Stopwatch()
    logger().info(
        f"***** Starting TCP Socket creation and data transfer for {round((test_run_time / 60), 2)} min *****")
    while sw.elapsed_sec <= test_run_time:
        time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
        logger().info(f"Remaining time to complete test is '{time_left}' minutes")
        logger().info("***** Initiating TCP TX traffic from DUT *****")
        run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol, iperf_time=200)
        time.sleep(30)

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the beacon frame in sniffer **********")
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], "not found beacon from DUT"
    logger().info("********* Beacon found from DUT********")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                     f'!(wlan.fc.type_subtype == 0x0008)  or' \
                     f'(wlan.fc.type_subtype == 0x0000)  or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

    logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
    wifi_client.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.wireless_deinit()


# @pytest.mark.skip()
@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "client_socket_limit": 10,
        "server_socket_limit": 0,
        "security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={"security": "WPA2", "ssid": "RS9116_AP", "passphrase": "12345678", "interface": "wlan0",
          "channel": 11, }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_UDP_Socket_Create_Transfer_Terminate_30min_C19481(wifi_sniffer, net_perf_client, wifi_dut, wifi_client,
                                                                 protocol, channel, utf_constants, teardown):
    validation = True
    test_run_time = utf_constants.get('time_duration')
    ping_count = utf_constants.get('ping_count')
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_UDP_Tx_30min_C19481')
    time.sleep(3)

    ip_dict = wifi_dut.interfaces.wifi.ip
    if not ip_dict:
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(mode=mode, static_ip=static_ip,
                                                         static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(10)
    logger().info(" ********** Started DUT as an AP ********* ")

    logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
    client_join(wifi_client, ssid="RS9116_AP")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {dut_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")

    logger().info("***** Pinging to DUT from wifi_client  *****")
    ping_from_client(dut_ip, ping_count)
    logger().info("***** Ping successful *****")
    time.sleep(5)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    raspi_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"Raspi-STA MAC_Address: {raspi_mac}")

    sw = Stopwatch()
    logger().info(
        f"***** Starting UDP Socket creation and data transfer for {round((test_run_time / 60), 2)} min *****")
    while sw.elapsed_sec <= test_run_time:
        time_left = round(((test_run_time - sw.elapsed_sec) / 60), 2)
        logger().info(f"Remaining time to complete test is '{time_left}' minutes")
        logger().info("***** Initiating UDP TX traffic from DUT *****")
        run_iperf_dut_as_client(wifi_dut, net_perf_client, host_ip, dut_ip, protocol, iperf_time=200)
        time.sleep(30)

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the beacon frame in sniffer **********")
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], "not found beacon from DUT"
    logger().info("********* Beacon found from DUT********")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {raspi_mac}) && (eapol) or ' \
                     f'!(wlan.fc.type_subtype == 0x0008)  or' \
                     f'(wlan.fc.type_subtype == 0x0000)  or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], "Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet in sniffer"

    logger().info("******* Initiating disconnection on STA(Raspberry pi)*******")
    wifi_client.interfaces.wifi.leave()
