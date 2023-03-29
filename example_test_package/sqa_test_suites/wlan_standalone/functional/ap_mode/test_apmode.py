import time
from datetime import datetime
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap, RS9116CoexMode, RS9116ConfigFeatureBitMap,
    RS9116StoreConfiguration, RS9116PowerSaveModes, RS9116DataRate)
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError
from utf.interfaces.shell.ssh_shell import SSHShell

"""Test Author = Rakesh Nayini 
    Reworked by CG, Rashmi & team

        1. Start the sniffer before connection
        2. Required A7 EVK(DUT) board 
        3. Stop the sniffer
        4. Initiate ping from the dut
        5. Analysing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4 - 2 and more
        4. Access Point(Third Party AP's)
"""

# Configuring static IP to DUT
mode = 'static'
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'
sleep_count = 300


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


def get_time_difference_between_two_beacons(wifi_sniffer, dut_mac_address, test_case, beacon_interval=100):
    remote_capture_file = wifi_sniffer.interfaces.capture.remote_capture_file
    logger().info(f"capture file is:{remote_capture_file}")

    wifi_sniffer.interfaces.capture.shell("sudo rm -rf *_beacons.*")
    filter1 = f'tshark -r {remote_capture_file} -Y "(wlan.fc.type_subtype eq 8) && (wlan.addr == {dut_mac_address})" -w {test_case}_beacons.pcap'
    remote_file = f'{test_case}_beacons.txt'
    filter2 = f'tshark -r "{test_case}_beacons.pcap" -Tfields -e "wlan.seq" -e "frame.time_relative" -c 10 > {remote_file}'
    logger().info("Creating only beacon filtered packets")
    wifi_sniffer.interfaces.capture.shell(filter1)
    wifi_sniffer.interfaces.capture.shell(f"sudo chmod +777 {remote_file}")
    logger().info("Getting list of beacon sequence and beacon intervals")
    wifi_sniffer.interfaces.capture.shell(filter2)
    wifi_sniffer.interfaces.capture.shell(f"sudo chmod +777 {remote_file}")

    if isinstance(wifi_sniffer.interfaces.capture.shell, SSHShell):
        current_time = time.time()
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
            file_time_stamp = str(datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
            local_file = f"./reports/{test_case}_beacons_{file_time_stamp}.txt"
            logger().info(local_file)
            sftp_main.get(remote_file, local_file)
            sftp_main.close()

    logger().info("Calculating time difference between two successive beacon frames")
    beacon_seq_time = {}
    with open(local_file) as f:
        for line in f:
            k, v = line.split()
            beacon_seq_time[int(k)] = float(v)
    sorted_seq_time = sorted(beacon_seq_time.items())
    time_difference = 0
    validation_range = range(beacon_interval - 10, beacon_interval + 10)
    for i in range(1, (len(sorted_seq_time) - 1)):
        sequence1 = sorted_seq_time[i][0]
        sequence1_time = sorted_seq_time[i][1]
        sequence2 = sorted_seq_time[i + 1][0]
        sequence2_time = sorted_seq_time[i + 1][1]
        if sequence2 - sequence1 == 1:
            time_difference = int(round((sequence2_time - sequence1_time), 3) * 1000)
            logger().info(f"Time difference between beacon sequence{sequence1, sequence2} is {time_difference}ms")
        if time_difference in validation_range:
            break
    assert time_difference in validation_range, "Unable to find expected time difference between 2 beacons"
    logger().info("Time difference between 2 successive beacon is within the range as expected")


def ping_from_client(wifi_client, dut_ip, ping_count=10):
    logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to DUT")
    client_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Client IP **********: {client_ip}")
    for count in range(3):
        try:
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dut_ip}")
            assert rc == 0
            logger().info(f"\n{stdout}\n")
            return rc == 0
        except:
            time.sleep(10)


pytestmark = [pytest.mark.firmware_app("test_ap_ht_caps")]


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19455", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "EU",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19455",
            "passphrase": "12345678",
            "country": "GE",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [13])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_dut_ap_mode_tx_rules_EUregion_C19455(firmware_loader, wifi_sniffer, wifi_dut, wifi_clients, channel,
                                              utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    validation = True
    ping_count = utf_constants.get("ping_count")
    logger().info("********* Configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("******* Start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19455')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(10)

    logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
    for i in range(0, len(wifi_clients)):
        connected = False
        logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
        wifi_clients[i].interfaces.wifi.join()
        time.sleep(5)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        for count in range(3):
            try:
                logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                status = ping_from_client(wifi_clients[i], dut_ip)
                assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                connected = True
                break
            except:
                logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                time.sleep(10)
        assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

    logger().info("Waiting 30 seconds to check connection stability")
    time.sleep(30)
    logger().info("Checking the connection stability after 30 seconds")
    for i in range(0, len(wifi_clients)):
        logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
        status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
        assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
        logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "EU")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {dut_mac_address}'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                              packet_filter1)[
        "packet_count"], "Unable to find beacon frame with Region EU in Sniffer"
    logger().info("*********Identified the beacons from DUT AP with region set to Europe*********")

    for i in range(0, len(wifi_clients)):
        logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
        wifi_clients[i].interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19456", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "JP",
    }
)
# channel 14 is not supported by raspberrypi
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": 13,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [13])
# channel 14 is not supported by raspberrypi
def test_dut_ap_mode_tx_rules_JPregion_C19456(firmware_loader, wifi_sniffer, wifi_dut, wifi_clients, channel,
                                              utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    validation = True
    ping_count = utf_constants.get("ping_count")
    logger().info("********* Configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("******* Start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19455')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(10)

    logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
    for i in range(0, len(wifi_clients)):
        connected = False
        logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
        wifi_clients[i].interfaces.wifi.join()
        time.sleep(5)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        for count in range(3):
            try:
                logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                status = ping_from_client(wifi_clients[i], dut_ip)
                assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                connected = True
                break
            except:
                logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                time.sleep(10)
        assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

    logger().info("Waiting 30 seconds to check connection stability")
    time.sleep(30)
    logger().info("Checking the connection stability after 30 seconds")
    for i in range(0, len(wifi_clients)):
        logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
        status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
        assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
        logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "JP")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {dut_mac_address}'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation,
                                                              packet_filter1)[
        "packet_count"], "Unable to find beacon frame with Region JP in Sniffer"
    logger().info(f"*********Identified the beacons from DUT AP with region set to Japan*********")

    for i in range(0, len(wifi_clients)):
        logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
        wifi_clients[i].interfaces.wifi.leave()



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
        "security": "WPA2", "ssid": "SILABS_AP_C19454", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "interface": "wlan0",
            "channel": 11,
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_dut_ap_mode_tx_rules_USregion_C19454(firmware_loader, wifi_sniffer, wifi_dut, wifi_clients, channel,
                                              utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    validation = True
    ping_count = utf_constants.get("ping_count")
    logger().info("********* Configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("******* Start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19454')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(10)

    logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
    for i in range(0, len(wifi_clients)):
        connected = False
        logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
        wifi_clients[i].interfaces.wifi.join(ssid="SILABS_AP_C19454")
        time.sleep(5)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        for count in range(3):
            try:
                logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                status = ping_from_client(wifi_clients[i], dut_ip)
                assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                connected = True
                break
            except:
                logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                time.sleep(10)
        assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

    logger().info("Waiting 30 seconds to check connection stability")
    time.sleep(30)
    logger().info("Checking the connection stability after 30 seconds")
    for i in range(0, len(wifi_clients)):
        logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
        status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
        assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
        logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "US")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {dut_mac_address}'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
        "Unable to find beacon frame with Region US in Sniffer"
    logger().info("*********Identified the beacons from DUT AP with region set to US*********")

    for i in range(0, len(wifi_clients)):
        logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
        wifi_clients[i].interfaces.wifi.leave()

@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19434", "passphrase": "12345678", "beacon": 100,
        "region_code_ap": "US",
    },
)
@pytest.mark.wifi_5g
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19434",
        "passphrase": "12345678",
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("channel", [36, 40, 48, 149, 165])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
def test_dut_ap_in_5GHz_various_channels_C19434(firmware_loader, wifi_sniffer, net_perf_client, wifi_dut, wifi_client,
                                                channel, protocol, utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    ping_count = utf_constants.get("ping_count")
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    file_name = f'test_DUTAP_in_5GHz_ch_{channel}'

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(3)
    logger().info(f"++++++ CAPTURE_FILE NAME IS {file_name}")

    logger().info(f" ********** Starting the DUT as an AP in Channel {channel} ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)

    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    wifi_client.interfaces.wifi.join()
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {dut_ip}")

    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info('********** Ping between AP and STA successful **********')

    logger().info('********** preparing iperf **********')
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol)
    logger().info('********** creating results object for sharing between host and dut **********')
    result = Result(net_perf_client.interfaces.net_perf.protocol)
    logger().info('********** open socket and start listening **********')
    with wifi_dut.interfaces.wifi.start_socket_reader(
            log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
            result=result,
            protocol=net_perf_client.interfaces.net_perf.protocol,
            port=net_perf_client.interfaces.net_perf.client_port,
            device_ip=dut_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
        logger().info('********** start iperf **********')
        net_perf_client.interfaces.net_perf.start()
        logger().info('********** capture device output **********')
        wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)
    logger().info('********** get and print throughput **********')
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None, 'unable to retrieve throughput information'
    __print_throughput(tp)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating time difference between 2 beacons")
    get_time_difference_between_two_beacons(wifi_sniffer, dut_mac_address, test_case="test_C19434", beacon_interval=100)

    logger().info('********** Validating Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {dut_mac_address})'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast),authentication,association,eapol packet in sniffer")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19444",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("dtim_period", [1, 2, 3, 6, 10])
@pytest.mark.parametrize("channel", [11])
def test_DUTAP_various_DTIM_C19444(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, dtim_period, channel,
                                   utf_constants):
    ping_count = utf_constants.get("ping_count")
    beacon = 100
    validation = True
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    file_name = f'test_DTIM_{dtim_period}_C19444'
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    time.sleep(3)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(dtim_period=dtim_period, channel=channel)
    time.sleep(10)

    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19444")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(f"********* Starting Ping********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, "Client failed to ping DUT"
    logger().info(f"********* Ping between AP and STA successful********* ")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info('********** Validating Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {dut_mac_address})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast),authentication,association,eapol packet in sniffer")

    logger().info("*********Validating the DTIM period **********")
    packet_filter2 = f'(wlan.fc.type_subtype==0x0008) and (wlan.tim.dtim_period == {dtim_period}) and (wlan.addr == {dut_mac_address})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f"Unable to find dtim period:{dtim_period} packet"
    logger().info(f"*********Validation of DTIM period:{dtim_period} is success **********")

    logger().info('********** Validating Beacon interval **********')
    packet_filter2 = f'(wlan.fc.subtype == 8) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.beacon == {beacon}) && (wlan.ds.current_channel == {channel})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f'Beacon interval {beacon} frame packets not found in sniffer'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19443", "passphrase": "12345678",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19443",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("beacon", [100, 200, 600, 1000])
@pytest.mark.parametrize("channel", [11])
# beacon interval 600, 1000 not working
def test_DUTAP_diff_beacon_intervals_C19443(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, beacon, channel,
                                            utf_constants):
    if beacon in [600, 1000]:
        pytest.skip(
            f"Beacon interval '{beacon}' not working, Raspi-STA is not finding DUT-AP for beacon interval '{beacon}'")

    ping_count = utf_constants.get("ping_count")
    validation = True
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f'test_C19443_{beacon}')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP *********")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    time.sleep(10)

    logger().info("********** Raspberry pi Client connected to DUT AP*********")
    wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19443")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info("********* Starting Ping********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, "Client failed to ping DUT, Raspi-STA disconnected from DUT-AP"
    logger().info("********* Ping between AP and STA successful*********")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Waiting 30 seconds to check connection stability")
    time.sleep(30)
    logger().info("*********Checking the connection stability after 30sec**********")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, "Client failed to ping DUT, Raspi-STA disconnected from DUT-AP"
    logger().info(f"DUT-AP and  RASPI-STA connected after 30 sec")

    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info('********** Validate Beacon frame **********')
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        "packet_count"], 'Beacon frame packets not found in sniffer'

    logger().info('********** Validating Beacon interval **********')
    packet_filter2 = f'(wlan.fc.subtype == 8) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.beacon == {beacon}) && (wlan.ds.current_channel == {channel})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f'Beacon interval {beacon} frame packets not found in sniffer'

    logger().info('********** Validating Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {dut_mac_address})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        "packet_count"], 'Probe request packets not found in sniffer'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.FiveGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19435", "passphrase": "12345678", "beacon": 100,
    }
)
@pytest.mark.wifi_5g
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19435",
        "passphrase": "12345678",
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_DUTAP_errorneous_band_config_C19435(firmware_loader, wifi_sniffer, wifi_dut, wifi_client):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    with pytest.raises(AssertionError) as exc_info:
        logger().info(" ********** Starting the DUT as AP in channel '10' ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=10)
    assert "Device must be initialized for the correct band" in str(exc_info)
    logger().info("Received exception ** Device must be initialized for the correct band...error_code:0x000A**")
    logger().info("Hence Passing the test case")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19432", "passphrase": "12345678",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUPAP_multiclient_connect_disconnect_C19432(firmware_loader, wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                     utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    validation = True
    beacon = 100
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19432')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    time.sleep(10)

    logger().info(f"********** number of wifi_clients:{len(wifi_clients)} **********")
    for iteration in range(iter_count):
        for i in range(0, len(wifi_clients)):
            connected = False
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            for count in range(3):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
                    assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                    connected = True
                    break
                except:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

        for i in range(0, len(wifi_clients)):
            logger().info(f'RASPI-STA{i} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        time.sleep(10)
        logger().info(f"Raspi Stations Connected and Disconnected for iteration:'{iteration + 1}'")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info('********** Validating Beacon interval **********')
    packet_filter2 = f'(wlan.fc.subtype == 8) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.beacon == {beacon}) && (wlan.ds.current_channel == {channel})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f'Beacon interval {beacon} frame packets not found in sniffer'

    logger().info('********** Validating Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast),authentication,association,eapol packet in sniffer")


# @pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19430_C19442", "passphrase": "12345678", "region_config": 0,
        "beacon": 100,
        "region_code_ap": "US",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19430_C19442",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19430_C19442",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19430_C19442",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19430_C19442",
            "passphrase": "12345678",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_DUTAP_Max_STAs_Connect_and_Ping_C19430_C19442(firmware_loader, wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                       utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    ping_count = utf_constants.get("ping_count")
    validation = True
    beacon = 100
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19430_C19442')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(10)

    logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
    for i in range(0, len(wifi_clients)):
        connected = False
        logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
        wifi_clients[i].interfaces.wifi.join()
        time.sleep(5)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        for count in range(3):
            try:
                logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                status = ping_from_client(wifi_clients[i], dut_ip)
                assert status, f"RASPI-STA{i + 1} failed to ping DUT"
                connected = True
                break
            except:
                logger().info(f"RASPI-STA{i + 1} failed to ping DUT...retry count -> {count + 1}")
                time.sleep(10)
        assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"

    logger().info("Waiting 30 seconds to check connection stability")
    time.sleep(30)
    logger().info("Checking the connection stability after 30 seconds")
    for i in range(0, len(wifi_clients)):
        logger().info(f"Initiating wlan ping from RASPI_STA{i + 1} for ping_count:{ping_count}")
        status = ping_from_client(wifi_clients[i], dut_ip, ping_count)
        assert status, f"Failed to ping DUT...RASPI-STA{i + 1} is disconnected from DUT-AP"
        logger().info(f"RASPI_STA{i + 1} is still connected to DUT-AP")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info('********** Validating Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], (
        "Unable to find Probe req(Broadcast/Unicast),authentication,association,eapol packet in sniffer")

    logger().info('********** Validating Beacon interval **********')
    packet_filter2 = f'(wlan.fc.subtype == 8) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.beacon == {beacon}) && (wlan.ds.current_channel == {channel})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f'Beacon interval {beacon} frame packets not found in sniffer'

    logger().info("********** Validating association ID's in assoc response **********")
    packet_filter4 = f'(wlan.fc.type_subtype==1) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.aid==1 || wlan.fixed.aid==2 || wlan.fixed.aid==3 || wlan.fixed.aid==4)'
    result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)['packet_count']
    if not result:
        logger().info("Unable to find assoc response packet...but connection and ping got successful")

    raspi_mac_address = []
    for i in range(0, len(wifi_clients)):
        logger().info(f"********** Validating qos data packets from RASPI-STA{i + 1} **********")
        raspi_mac_address.append(wifi_clients[i].interfaces.wifi.get_mac_address())
        logger().info(f"RASPI-STA{i + 1}_MAC_Address: {raspi_mac_address[i]}")
        packet_filter3 = f'(wlan.bssid == {dut_mac_address}) && (wlan.sa=={raspi_mac_address[i]}) && (wlan.fc.type_subtype == 0x0028)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], f'Unable to find qos data packets from RASPI-STA{i + 1}'

    for i in range(0, len(wifi_clients)):
        logger().info(f'Initiating Disconnection on RASPI-STA{i + 1}')
        wifi_clients[i].interfaces.wifi.leave()


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19436", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19436",
        "passphrase": "12345678",
        "channel": 10,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.parametrize("channel", [10])
# @pytest.mark.firmware_app("test_ap_ht_caps")
def test_DUTAP_verify_beacon_format_C19436(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel,
                                           utf_constants):
    ping_count = utf_constants.get("ping_count")
    beacon = 100
    validation = True
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19436')
    time.sleep(3)

    logger().info("********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.set_htcaps()
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(10)

    logger().info(" ********** Raspberry Pi client connecting to DUT ********* ")
    wifi_client.interfaces.wifi.join()
    time.sleep(10)
    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"********* Dut IP **********: {dut_ip}")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, "Failed to ping DUT...RASPI-STA is disconnected from DUT-AP"

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info('********** Validate Beacon frame **********')
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
        "Unable to find beacon frame"

    logger().info('********** Validating Beacon interval **********')
    packet_filter2 = f'(wlan.fc.subtype == 8) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.beacon == {beacon}) && (wlan.ds.current_channel == {channel})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f'Beacon interval {beacon} frame packets not found in sniffer'

    logger().info('********** Validating HT_IE in Beacon frame **********')
    packet_filter3 = f'(wlan.sa == {dut_mac_address}) and (wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 )'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)["packet_count"], \
        "Unable to find HT_IE info in beacon frame"


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
        "security": "WPA2", "ssid": "SILABS_AP_C19437", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19437",
        "passphrase": "123456789",
        "interface": "wlan0",
        "channel": 10,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
def test_apmode_connectivity_with_wrong_psk_Cli_C19437(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel):
    validation = True
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_apmode_connectivity_with_wrong_psk_Cli19437')
    time.sleep(3)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(5)

    try:
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join()
        time.sleep(5)
    except:
        logger().info(f"connectivity fails as PSK is given wrong -->Expected")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 10 || wlan.fc.type_subtype == 12))'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
        "Unable to find de-auth or disassoc packets in sniffer"
    logger().info(f"*********found de-auth or disassoc packets in sniffer*********")


# ###############################19441########################
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
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
        "data_rates": RS9116DataRate.Mbps_54,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP",
        "passphrase": "12345678",
        "interface": "wlan0",
        "channel": 10,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_DUT_APMode_fixed_data_rate_C19441(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel, protocol,
                                           net_perf_client, utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    ping_count = utf_constants.get("ping_count")
    validation = True
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_fixed_datarate_C19441')
    time.sleep(3)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(5)

    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    wifi_client.interfaces.wifi.join()
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(" ********** Starting ping ********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        dut_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && wlan.fc.type_subtype==40 && radiotap.datarate ==54'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "not found data packets with 54 Mbps data rate"
    logger().info(f"*********data packets transmitted with 54 Mbps data rate*********")


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
        "security": "WPA2", "ssid": "SILABS_AP_C19446", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "dtim": 4,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19446",
        "passphrase": "12345678",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
# @pytest.mark.firmware_app("test_ap_ht_caps")
def test_DUT_APMode_11n_htcaps_support_C19446(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel, protocol,
                                              net_perf_client, utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    ping_count = utf_constants.get("ping_count")
    validation = True

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19446')
    time.sleep(3)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.set_htcaps()
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(5)

    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    wifi_client.interfaces.wifi.join()
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(" ********** Starting ping ********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # starting iperf server at raspi client
    logger().info("configuring iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip,
                                                    protocol=protocol)
    logger().info("starting iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        dut_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)

    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the beacon frame in sniffer **********")
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], "not found beacon from DUT "
    logger().info("*********beacon found from DUT********")

    logger().info("***** Validating HT_IE *****")
    packet_filter1 = f'(wlan.sa == {dut_mac_address}) and (wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 )'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
        "Unable to find HT_IE in beacon"


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19447", "passphrase": "12345678", "dtim": 4,
        "region_code_ap": "US ",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19447",
        "passphrase": "12345678",
        "interface": "wlan0",
        "channel": 11,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("beacon", [100, 200, 300])
# @pytest.mark.firmware_app("test_ap_ht_caps")
def test_DUTAP_TCP_Tx_Rx_C19447(firmware_loader, wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol,
                                channel, beacon, utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    validation = True
    ping_count = utf_constants.get("ping_count")
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"test_C19447_{beacon}")
    time.sleep(3)

    logger().info(" ********** Starting the DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.set_htcaps()
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    time.sleep(5)

    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19447")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {dut_ip}")

    logger().info(f"*********starting the Ping **********")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # starting iperf for TX
    logger().info("***** starting iperf for TX *****")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=dut_ip, protocol=protocol)
    net_perf_client.interfaces.net_perf.start()
    # open socket and send traffic
    logger().info("***** open socket and send traffic *****")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        dut_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    # get and print throughput
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)
    time.sleep(10)

    # preparing iperf for RX
    logger().info("***** preparing iperf for RX *****")
    net_perf_client.interfaces.net_perf.client_options["host_role"] = IperfConstants.CLIENT_MODE
    # verifying host_ip
    status = ping_from_client(wifi_client, dut_ip)
    assert status, "Client failed to ping DUT, Raspi-STA disconnected from DUT-AP"
    net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=dut_ip, protocol=protocol)
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
            device_ip=dut_ip,
            data_len=net_perf_client.interfaces.net_perf.client_data_len,
            time=net_perf_client.interfaces.net_perf.client_timeout) as rx_obj:
        # start iperf
        logger().info("***** start iperf *****")
        net_perf_client.interfaces.net_perf.start()
        time.sleep(3)
        # capture device output
        logger().info("***** capture device output *****")
        wifi_dut.interfaces.wifi.read_from_device(rx_obj, net_perf_client.interfaces.net_perf.client_timeout)
    time.sleep(5)
    # get and print throughput
    logger().info("***** get and print throughput *****")
    tp = net_perf_client.interfaces.net_perf.process_output(result)
    assert tp is not None, 'Unable to print throughput information'
    __print_throughput(tp)

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validating Beacon HT_IE
    logger().info("***** Validating HT_IE *****")
    packet_filter1 = f'(wlan.sa == {dut_mac_address}) and (wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 )'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
        "Unable to find HT_IE in beacon"

    logger().info('********** Validating Beacon interval **********')
    packet_filter2 = f'(wlan.fc.subtype == 8) && (wlan.addr == {dut_mac_address}) && (wlan.fixed.beacon == {beacon}) && (wlan.ds.current_channel == {channel})'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        "packet_count"], f'Beacon interval {beacon} frame packets not found in sniffer'

    logger().info(f"*********Disconnecting from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()


# ##########19448##################
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
        "security": "WPA2", "ssid": "SILABS_AP_C19447", "passphrase": "12345678", "dtim": 4,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19448",
        "passphrase": "12345678",
        "interface": "wlan0",
    },
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.firmware_app("test_ap_ht_caps")
def test_DUT_APMode_11d_support_C19448(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, utf_constants):
    ping_count = utf_constants.get("ping_count")
    bands = [RS9116Band.TwoPointFourGHz, RS9116Band.FiveGHz]
    regions = ["US", "JP", "EU"]

    for band in bands:
        for region in regions:
            logger().info(f"********* Initiating DUT AP test with band:{band} and region:{region} *********")
            wifi_dut.interfaces.wifi.reset_soft()
            time.sleep(2)
            wifi_dut.interfaces.wifi.init(region_code_ap=region, band=band)

            validation = True
            channel = 11 if band == RS9116Band.TwoPointFourGHz else 40
            logger().info("********* configuring static ip to DUT *********")
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                             static_gateway=static_gateway)

            logger().info("********* configuring the sniffer with access point channel *********")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

            logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f'test_C19448_{band}')
            time.sleep(3)

            logger().info(" ********** Starting DUT as an AP ********* ")
            wifi_dut.interfaces.wifi.set_htcaps()
            wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_C19448", security="WPA2", passphrase="12345678",
                                              channel=channel)
            time.sleep(5)

            logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
            country = region
            if region == "EU": country = "GE"
            wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19448", country=country)
            time.sleep(10)

            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")

            logger().info(" ********** Starting ping ********* ")
            status = ping_from_client(wifi_client, dut_ip, ping_count)
            assert status, f"Client failed to ping DUT"
            logger().info(" ********** Ping successful ********* ")
            logger().info(f"*********RASPI_STA connected to DUT AP**********")

            logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
            wifi_client.interfaces.wifi.leave()

            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")

            logger().info("Stop sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating Beacon HT_IE
            logger().info("***** Validating HT_IE *****")
            packet_filter1 = f'(wlan.sa == {dut_mac_address}) and (wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 )'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
                "Unable to find HT_IE in beacon"

            logger().info(f"*********Validating the Sniffer Packet **********")
            packet_filter1 = f'((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 8) && (wlan.country_info.code == {region}))'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
                "Unable to find beacon frame with region code  in Sniffer"


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
        "band": RS9116Band.FiveGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP_C19457",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "JP ", "channel": 149,
    },
)
@pytest.mark.wifi_dualband
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_DUTAP_JPregion_unsupported_channel_C19457(firmware_loader, wifi_dut):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    with pytest.raises(WlanError) as exc_info:
        logger().info(" ********** Starting DUT as an AP with region as JP and channel as 149 ********* ")
        wifi_dut.interfaces.wifi.start_ap()
    assert exc_info.value.error_code == 0xA, "Desired error code is not received, failing the test"
    logger().info("Found the desired error code 0xA, marking the test case passed")


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
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ", "channel": 14,

    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_DUTAP_USregion_unsupported_channel_C19458(wifi_dut):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    with pytest.raises(WlanError) as exc_info:
        logger().info(" ********** Starting DUT as an AP with region as US and channel as 14 ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=14)
        logger().info(f"error code received:{exc_info.value.error_code}")
    assert exc_info.value.error_code == 0xA, "Did not receive the desired error code from DUT, failing the test"
    logger().info("Found the desired error code 0xA, marking the test case passed")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.WiFiClient,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.DHCPv4Client
                          | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19449", "passphrase": "test1234", "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19449",
        "passphrase": "test1234",
        "channel": 11,
        "interface": "wlan0",
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'external_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_soft_reset_sta_to_ap_C19449(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel,
                                         wifi_access_point,
                                         utf_constants):
    ping_count = utf_constants.get("ping_count")
    validation = True
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_softreset_statoap_C19449')
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("DUT-STA joining into Wi-Fi")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f'dut ip is :{dut_ip_as_client}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    status = ping(dut_ip_as_client, ping_count)
    assert status, f"DUT failed to ping AP"

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating probe request packet in sniffer")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 && wlan.sa=={dut_mac_address} && wlan.da==ff:ff:ff:ff:ff:ff'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "Unable to find probe req from dut in sniffer"

    logger().info("Validating assoc request,response and eapol packets in sniffer")
    packet_filter2 = f'(wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        "Unable to find assoc req or resp packet in Sniffer"

    logger().info("Validating qos data packets")
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.type_subtype == 0x0028)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets in sniffer'

    # logger().info("passing passphrase and ssid to decrypt dhcp packets")
    # decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    # logger().info(f"decryption_key is '{decryption_key}'")
    # status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    # logger().info(f'DHCP packet from DUT found: {status}')
    # assert status, "DHCP packet not found"

    # deinit
    logger().info("Initiating wireless de init")
    wifi_dut.interfaces.wifi.wireless_deinit()

    logger().info("Initiating wireless init to change DUT STA mode to AP Mode ")
    wifi_dut.interfaces.wifi.dut_init(oper_mode=6, coex_mode=9, retries=3)

    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(oper_mode=6, coex_mode=9)

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer when DUT is in AP mode ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_Trnms_rules_USregion_C19449')
    time.sleep(3)

    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=100, channel=channel)
    time.sleep(10)

    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19449", channel=channel, passphrase="test1234")
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    rasp_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"raspi_mac:{rasp_mac}")
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(" ********** Starting ping ********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    packet_filter3 = f'wlan.fc.type_subtype == 0x0008 && wlan.sa=={dut_mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)["packet_count"], \
        "Unable to find beacon frame from DUT  in Sniffer"


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19450", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "dtim": 4,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'external_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19450",
        "passphrase": "12345678",
        "interface": "wlan0",
        "channel": 11,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_AP_Mode_soft_reset_ap_to_sta_C19450(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel,
                                                 wifi_access_point, utf_constants):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)
    ping_count = utf_constants.get("ping_count")
    validation = True

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19450_dut_ap')
    time.sleep(3)

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(5)

    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    wifi_client.interfaces.wifi.join()
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(" ********** Starting ping ********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    raspi_mac_address = wifi_client.interfaces.wifi.get_mac_address()
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"raspi_mac:{raspi_mac_address}")

    logger().info("Stop sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating beacon frame in sniffer capture")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0008 && wlan.sa=={dut_mac_address}'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "Unable to find beacon frame from DUT  in Sniffer"

    logger().info("Validating qos data packets")
    packet_filter3 = f'(wlan.bssid == {dut_mac_address}) && (wlan.sa=={raspi_mac_address}) && (wlan.fc.type_subtype == 0x0028)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets'

    logger().info(" ********** Raspberry Pi Client disconnecting from DUT-AP ********* ")
    wifi_client.interfaces.wifi.leave()

    # deinit
    logger().info("Initiating wireless de init")
    wifi_dut.interfaces.wifi.wireless_deinit()

    logger().info("Initiating wireless init to change DUT AP mode to STA Mode ")
    wifi_dut.interfaces.wifi.dut_init(oper_mode=0, coex_mode=9, retries=3)

    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(oper_mode=0, coex_mode=9)

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19450_dut_sta')
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("DUT-STA joining into Wi-Fi")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip_as_client = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f'dut ip is :{dut_ip_as_client}')

    logger().info("pinging to dut.....")
    status = ping(dut_ip_as_client, ping_count)
    assert status, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating probe request packet in sniffer")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 && wlan.sa=={dut_mac_address} && wlan.da==ff:ff:ff:ff:ff:ff'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "Unable to find probe req from dut in sniffer"

    logger().info("Validating assoc request,response and eapol packets in sniffer")
    packet_filter2 = f'(wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
        "Unable to find assoc req or resp packet in Sniffer"

    logger().info("Validating qos data packets")
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.type_subtype == 0x0028)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets in sniffer'

    # logger().info("passing passphrase and ssid to decrypt dhcp packets")
    # decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    # logger().info(f"decryption_key is '{decryption_key}'")
    # status = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    # logger().info(f'DHCP packet from DUT found: {status}')
    # assert status, "DHCP packet not found"


# ###########store_configuration##################
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
        "security": "Open", "ssid": "SILABS_AP_C19451", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "Open",
        "ssid": "SILABS_AP_C19451",
        "interface": "wlan0",
        "channel": 11,
    },
)
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_AP_Mode_store_config_C19451(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel, utf_constants):
    ping_count = utf_constants.get("ping_count")
    try:
        validation = True
        dut_ip = wifi_dut.interfaces.wifi.ip
        logger().info(f"********* Dut IP **********: {dut_ip}")
        if not dut_ip:
            logger().info("********* configuring static ip to DUT *********")
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                             static_gateway=static_gateway)

        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_store_config_C19451')
        time.sleep(3)

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(10)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19451")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        logger().info(" ********** Starting ping ********* ")
        status = ping_from_client(wifi_client, dut_ip, ping_count)
        assert status, f"Client failed to ping DUT"
        logger().info(" ********** Ping successful ********* ")
        logger().info(f"*********RASPI_STA connected to DUT AP**********")

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("*********Validating the beacon frame in Sniffer **********")
        packet_filter1 = f'((wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype==8))'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
            "Unable to find beacon frame in Sniffer"

        logger().info("*********Validating the assoc request,assoc response frame in Sniffer **********")
        packet_filter2 = f'(wlan.addr=={dut_mac_address})||(wlan.fc.type_subtype==0||wlan.fc.type_subtype==1||icmp)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)["packet_count"], \
            "unable to find assoc request,assoc response packets in sniffer"

        logger().info("Save the wireless configuration in the DUT")
        wifi_dut.interfaces.wifi.config_save()
        logger().info("Enable the wireless configuration in the DUT")
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        time.sleep(20)

        for count in range(3):
            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=6, coex_mode=9, retries=0)
            if exc_info.value.error_code == 0x5A5A:
                status = True
                break
            else:
                logger().info(f"retry count:{count}")
                status = False
                continue
        assert status, "Wrong error code found from DUT"
        time.sleep(20)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19451")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        logger().info(" ********** Starting ping ********* ")
        status = ping_from_client(wifi_client, dut_ip, ping_count)
        assert status, f"Client failed to ping DUT"
        logger().info(" ********** Ping successful ********* ")
        logger().info(f"*********RASPI_STA connected to DUT AP**********")

        logger().info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("*********Validating the beacon frame in Sniffer **********")
        packet_filter1 = f'((wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype==8))'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
            "Unable to find beacon frame in Sniffer"

        logger().info("*********Validating the assoc request,assoc response frame in Sniffer **********")
        packet_filter2 = f'(wlan.addr=={dut_mac_address})||(wlan.fc.type_subtype==0||wlan.fc.type_subtype==1||icmp)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)["packet_count"], \
            "unable to find assoc request,assoc response packets in sniffer"

    except Exception as error:
        logger().info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        time.sleep(5)
        logger().info("clean_up_dut")
        wifi_dut.interfaces.wifi.reset()
        raise error


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
        "security": "WPA2", "ssid": "SILABS_AP_C19452", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_C19452",
        "passphrase": "12345678",
        "interface": "wlan0",
        "channel": 11,
    },
)
@pytest.mark.store_config
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_AP_Mode_store_config_wpa2_C19452(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel,
                                              utf_constants):
    ping_count = utf_constants.get("ping_count")
    try:
        validation = True
        dut_ip = wifi_dut.interfaces.wifi.ip
        logger().info(f"********* Dut IP **********: {dut_ip}")
        if not dut_ip:
            logger().info("********* configuring static ip to DUT *********")
            wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                             static_gateway=static_gateway)

        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_store_config_wpa2_C19452')
        time.sleep(3)

        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        time.sleep(10)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19452")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        logger().info(" ********** Starting ping ********* ")
        status = ping_from_client(wifi_client, dut_ip, ping_count)
        assert status, f"Client failed to ping DUT"
        logger().info(" ********** Ping successful ********* ")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info(f"*********RASPI_STA connected to DUT AP**********")
        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("*********Validating the beacon frame in Sniffer **********")
        packet_filter1 = f'((wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype==8))'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
            "Unable to find beacon frame in Sniffer"

        logger().info("*********Validating the assoc request,assoc response frame in Sniffer **********")
        packet_filter2 = f'(wlan.addr=={dut_mac_address})||(wlan.fc.type_subtype==0||wlan.fc.type_subtype==1||icmp)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)["packet_count"], \
            "unable to find assoc request,assoc response packets in sniffer"

        logger().info("Save the wireless configuration in the DUT")
        wifi_dut.interfaces.wifi.config_save()
        logger().info("Enable the wireless configuration in the DUT")
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
        time.sleep(20)

        for count in range(3):
            logger().info("Initiating wireless de init")
            wifi_dut.interfaces.wifi.wireless_deinit()
            time.sleep(2)
            with pytest.raises(WlanError) as exc_info:
                logger().info("Initializing the DUT")
                wifi_dut.interfaces.wifi.dut_init(oper_mode=6, coex_mode=9, retries=0)
            if exc_info.value.error_code == 0x5A5A:
                status = True
                break
            else:
                logger().info(f"retry count:{count}")
                status = False
                continue
        assert status, "Wrong error code found from DUT"
        time.sleep(20)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_C19452")
        time.sleep(10)

        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        logger().info(" ********** Starting ping ********* ")
        status = ping_from_client(wifi_client, dut_ip, ping_count)
        assert status, f"Client failed to ping DUT"
        logger().info(" ********** Ping successful ********* ")
        logger().info(f"*********RASPI_STA connected to DUT AP**********")

        logger().info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)

        logger().info("Stopping sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("*********Validating the beacon frame in Sniffer **********")
        packet_filter1 = f'((wlan.addr=={dut_mac_address})&&(wlan.fc.type_subtype==8))'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], \
            "Unable to find beacon frame in Sniffer"

        logger().info("*********Validating the assoc request,assoc response frame in Sniffer **********")
        packet_filter2 = f'(wlan.addr=={dut_mac_address})||(wlan.fc.type_subtype==0||wlan.fc.type_subtype==1||icmp)'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            "packet_count"], "unable to find assoc request,assoc response packets in sniffer"

    except Exception as error:
        logger().info("Disable store configuration")
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        time.sleep(5)
        logger().info("clean_up_dut")
        wifi_dut.interfaces.wifi.reset()
        raise error


# This test case is not working [keep alive packets or deauth packets are not getting because some background task is always running in Raspi-STA].Hence this test case can not be automated.
@pytest.mark.skip("This test case is not working [keep alive packets or deauth packets are not getting because some background task is always running in Raspi-STA].Hence this test case can not be automated.")
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
        "interface": "wlan0",
        "channel": 10,
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
def test_DUT_APMode_raspi_sta_inactive_C19439(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel,
                                              utf_constants):
    ping_count = utf_constants.get("ping_count")
    validation = True
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                                         static_gateway=static_gateway)

    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_raspista_inactive_C19439')

    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    time.sleep(5)

    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    wifi_client.interfaces.wifi.join()
    time.sleep(10)

    dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    logger().info(f"********* Dut IP **********: {dut_ip}")

    logger().info(" ********** Starting ping ********* ")
    status = ping_from_client(wifi_client, dut_ip, ping_count)
    assert status, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info("no data transmission between dut ap and raspi sta for 5 min")
    time.sleep(sleep_count)

    # logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    # wifi_client.interfaces.wifi.leave()

    logger().info("Stopping sniffer capture")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 36 || wlan.fc.type_subtype == 12))'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        "Unable to find deauth or keep alive packet in Sniffer"
    logger().info(f"*********keep alive packets or deauth packets found in capture*********")

# def test_wifi_clients_get_mac_address(wifi_clients):
#     logger().info(f"********** Number of wifi_clients are:{len(wifi_clients)} **********")
#     primary_raspi_mac = wifi_clients[0].interfaces.wifi.get_mac_address()
#     logger().info(f"primary_raspi_mac: '{primary_raspi_mac}'")
#
#     secondary_raspi_mac = wifi_clients[1].interfaces.wifi.get_mac_address()
#     logger().info(f"secondary_raspi_mac: '{secondary_raspi_mac}'")
