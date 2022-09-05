import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116OperatingMode,
    RS9116Band,
    RS9116FeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116TCPIPFeatureBitMap,RS9116CoexMode,RS9116ConfigFeatureBitMap,
    RS9116StoreConfiguration,RS9116PowerSaveModes,RS9116DataRate)
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.cli import CLITransportException
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError

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
static_ip = '192.168.100.76'
static_subnet = '255.255.255.0'
static_gateway = '192.168.100.76'
ping_count = 30
sleep_count=300


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)

class cleanup_store_config():
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def dut_recovery(self):
        tries = 0
        while tries < 3:
            tries += 1
            try:
                logger().info("Initiating reset for device cleanup")
                self.wifi_dut.interfaces.wifi.reset_soft()
                time.sleep(2)
                self.wifi_dut.interfaces.wifi.associated = True
                logger().info("Initializing the DUT")
                self.wifi_dut.interfaces.wifi.wireless_init(oper_mode=6, coex_mode=9, retries=1)
                time.sleep(10)
                return True
            except:
                logger().info("clean up process failed ,retrying for 3 times")

    def disconnect(self):

        try:
            logger().info("Initiating disconnect for cleanup")
            self.wifi_dut.interfaces.wifi.leave()
            time.sleep(5)
            logger().info("cfg disable")
            # Enables the store configuration
            self.wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
            return True
        except:
            logger().info("clean up process failed")



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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_APMode_Trnms_rules_USregion_C19454(wifi_sniffer, wifi_dut, wifi_client, channel):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet, static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19454')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"*********Waiting 30 sec to check connection stability **********")
    time.sleep(30)
    logger().info(f"*********Checking the connection stability after 30sec**********")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"*********DUT AP is still connected to RASPI_STA**********")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "US")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find beacon frame with Region US in Sniffer"
    logger().info(f"*********Identified the beacons from DUT AP with region set to US*********")


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
        "country": "EU ",
        "channel":"13"
    },
)
@pytest.mark.parametrize("channel", [13])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_DUT_APMode_Trms_rules_EUregion_C19455(wifi_sniffer, wifi_dut, wifi_client, channel):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in EU region *********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19455')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    wifi_client.interfaces.wifi.get_mac_address()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"Ping between AP-STA successful")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"*********Waiting 30 sec to check connection stability **********")
    time.sleep(30)
    logger().info(f"*********Checking the connection stability after 30sec**********")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"*********DUT AP is connected to RASPI_STA after 30sec*********")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "EU")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find beacon frame with Region EU in Sniffer"
    logger().info(f"*********Identified the beacons from DUT AP with region set to Europe*********")



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
@pytest.mark.parametrize("channel", [13])
def test_test_DUT_APMode_Trms_rules_JPregion_C19456(wifi_sniffer, wifi_dut, wifi_client, channel):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in JP region *********")
    logger().info("Changing the validation channel to 13 to accomodate Sniffer Verification")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19456')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" **********Starting the ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"Ping between AP and STA successful")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"*********Waiting 30 sec to check connection stability **********")
    time.sleep(30)
    logger().info(f"*********Checking the connection stability after 30sec**********")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"DUT AP is connected to RASPI_STA after 30sec**********")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    logger().info(f"*********Validating the Sniffer Packet **********")
    packet_filter1 = f'((wlan.fc.type_subtype == 8) &&(wlan.country_info.code == "JP")) && (wlan.ds.current_channel == {channel})' \
                     f'&& wlan.addr == {mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), \
        "Unable to find beacon frame with Region JP in Sniffer"
    logger().info(f"*********Identified the beacons from DUT AP with region set to Japan*********")



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
def test_DUTAP_in_5GHz_variouschannels_C19434(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, channel, protocol):
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    file_name = f'test_DUTAP_in_5GHz_ch_{channel}'
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(f" ********** Starting the DUT as an AP in Channel {channel} ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {device_ip}")
    logger().info(f"******** Host IP ******** {host_ip}")
    assert wifi_client.interfaces.wifi.ping(server_ip=device_ip), "Client filed to ping AP"
    logger().info('********** Ping between AP and STA successful **********')
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
    assert tp is not None, 'unable to retrieve throughput information'
    __print_throughput(tp)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
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
def test_DUTAP_variousDTIM_C19444(wifi_sniffer, wifi_dut, wifi_client, dtim, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    file_name = f'test_DUTAP_with_DTIM_{dtim}'
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(2)
    wifi_dut.interfaces.wifi.start_ap(dtim_period=dtim, channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(f"********* Starting Ping********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"********* Ping between AP and STA successful********* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"*********Waiting 30 sec to check connection stability **********")
    time.sleep(30)
    logger().info(f"*********Checking the connection stability after 30sec**********")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"DUT-AP and  RASPI-STA connected after 30 sec")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    logger().info(f"*********Validating the Sniffer Packet **********")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"]
    logger().info(f"*********Validation of Beacon frame is success **********")
    logger().info(f"*********Validation of DTIM Intervals is Pending *********")


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
def test_DUTAP_diff_beacon_intvls_C19443(wifi_sniffer, wifi_dut, wifi_client, beacon, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19443')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    time.sleep(5)
    wifi_dut.interfaces.wifi.start_ap(beacon_interval=beacon, channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    time.sleep(10)
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connected to DUT AP********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(f"********* Starting Ping********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"********* Ping between AP and STA successful********* ")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    time.sleep(30)
    logger().info(f"*********Checking the connection stability after 30sec**********")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(f"DUT-AP and  RASPI-STA connected after 30 sec")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    logger().info(f"*********Validating the Sniffer Packet **********")
    logger().info('********** Validate Beacon frame **********')
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008)'
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info('********** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol **********')
    packet_filter4 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or ' \
                     f'(wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"], 'Beacon frame packets not found in sniffer'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)["packet_count"], 'Probe request packets not found in sniffer'



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
def test_DUTAP_errorneous_band_config_C19435(wifi_sniffer, wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    with pytest.raises(AssertionError) as exc_info:
        logger().info(" ********** Starting the DUT as AP in channel '10' ********* ")
        wifi_dut.interfaces.wifi.start_ap(channel=10)
    assert "Device must be initialized for the correct band" in str(exc_info)
    logger().info("Received exception ** Device must be initialized for the correct band**")
    logger().info("Hence Passing the test case")

@pytest.mark.skip()
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
def test_DUPAP_multiclient_connect_disconnect_C19432(wifi_sniffer, wifi_dut, wifi_clients, channel):
    logger().info(f'************* Configuring Static IP *************')
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    validation = True
    logger().info("********** configuring the sniffer with access point channel **********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    time.sleep(5)
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19432')
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_dut.interfaces.wifi.start_ap()
    for iteration in range(1):
        logger().info(f" ********** len(wifi_clients){len(wifi_clients)}")
        for i in range(0, len(wifi_clients)):
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(0.5)
            #logger().info(f'{wifi_clients[i]}')
            logger().info(f'Station :{i}')
            # assert (wifi_clients[i].interfaces.wifi.ping(
            #     server_ip=wifi_clients[i].interfaces.wifi.client_gateway_ip)), "Client failed to ping DUT"
            device_ip = wifi_clients.interfaces.wifi.client_gateway_ip
            logger().info(f"********* Dut IP **********: {device_ip}")
            status = ping(device_ip, ping_count)
            assert status == True, f"Client failed to ping DUT"
            logger().info(f"DUT-AP and  RASPI-STA connected after 30 sec")
            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {mac_address}")
            wifi_clients[i].interfaces.wifi.leave()
            logger().info(f'Station :{i} Disconnecting with AP')
            #time.sleep(10)
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

@pytest.mark.skip
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
def test_DUTAP_MaxSTAs_Connectandping_C19430_C19442(wifi_sniffer, wifi_dut, wifi_clients, channel):
    logger().info(f'************* Configuring Static IP *************')
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
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
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
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
def test_DUTAP_verify_beacon_format_C19436(wifi_sniffer, wifi_dut, wifi_client, channel):
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
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
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    logger().info('********** Validate Beacon frame **********')
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0008)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)["packet_count"]
    logger().info(f"*********Validation of Beacon Intervals pending **********")


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
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "beacon": 100,"dtim": 4,
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
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_DUTAP_TCPTx_C19447(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19447_Tx")
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting the DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {device_ip}")
    logger().info(f"******** Host IP ******** {host_ip}")
    logger().info(f"*********starting the Ping **********")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

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

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info("***** Validate Probe req(Broadcast/Unicast), authentication ,association, eapol *****")
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan_radio.channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b)'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ["packet_count"]
    #Need to check HT capability IE
    logger().info(f"*********Disconnecting from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()


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
        "security": "WPA2", "ssid": "SILABS_AP", "passphrase": "12345678", "beacon": 100,"dtim": 4,
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
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_DUTAP_TCPRx_C19447(wifi_sniffer, net_perf_client, wifi_dut, wifi_client, protocol, channel):
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********** configuring the sniffer with access point channel **********")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="test_C19447_Rx")
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"******** Dut IP ******** {device_ip}")
    logger().info(f"******** Host IP ******** {host_ip}")
    logger().info(" ********** Starting the Ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
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
    assert tp is not None, 'Unable to print throughput information'
    __print_throughput(tp)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    logger().info("***** Validate Beacon *****")
    packet_filter1 = f'(wlan.addr==mac_address) and (wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45) and (wlan.tag.number == 61)'
    logger().info(f"*********Disconnecting from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("***** Verifying the HT Capability in the beacon *****")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), ["packet_count"]
    logger().info("***** Identified the HT Capability IE's in the beacon *****")



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
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ", "channel": 14,

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
def test_DUTAP_USregion_unsupportedchannel_C19458(wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    with pytest.raises(WlanError) as exc_info:
        logger().info(" ********** Starting DUT as an AP with region as US and channel as 14 ********* ")
        wifi_dut.interfaces.wifi.start_ap()
        logger().info(f"error code received:{exc_info.value.error_code}")
    assert exc_info.value.error_code == 0xA,"Did not receive the desired error code from DUT, failing the test"
    logger().info("Found the desired error code 0xA, marking the test case passed")


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
def test_DUTAP_JPregion_unsupportedchannel_C19457(wifi_dut, wifi_client):
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    with pytest.raises(WlanError) as exc_info:
        logger().info(" ********** Starting DUT as an AP with region as JP and channel as 149 ********* ")
        wifi_dut.interfaces.wifi.start_ap()
    assert exc_info.value.error_code == 0xA,"Desired error code is not received, failing the test"
    logger().info("Found the desired error code 0xA, marking the test case passed")


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
        "passphrase": "123456789",
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_apmode_connectivity_with_wrong_psk_Cli19437(wifi_sniffer, wifi_dut, wifi_client, channel):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_apmode_connectivity_with_wrong_psk_Cli19437')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    try:
        wifi_client.interfaces.wifi.join()
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    except Exception as e:
        logger().info(f"connectivity fails as PSK is given wrong -->Expected")
    packet_filter1 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 10 || wlan.fc.type_subtype == 12))'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"*********Validating the Sniffer Packet **********")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find de-auth or disassoc packets in sniffer"
    logger().info(f"*********found de-auth or disassoc packets in sniffer*********")

##########19448##################

pytest.mark.wifi_client("raspi_wifi")
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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_APMode_11d_support_C19448(wifi_sniffer, wifi_dut, wifi_client, channel):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_11d_support_C19448')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"*********RASPI_STA connected to DUT AP**********")
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    packet_filter1 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 8) && (wlan.country_info.code == US))'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"*********Validating the Sniffer Packet **********")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find beacon frame with region code  in Sniffer"

# ##########store_configuration##################

pytest.mark.wifi_client("raspi_wifi")
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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_APMode_store_config_wpa2_C19452(wifi_sniffer, wifi_dut, wifi_client, channel):
    try:
        logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
        validation = True
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                          static_gateway=static_gateway)
        logger().info("********* configuring static ip to DUT *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("********* configuring the sniffer with access point channel *********")
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_store_config_wpa2_C19452')
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_client.interfaces.wifi.join()
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {device_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")
        logger().info(" ********** Starting ping ********* ")
        status = ping(device_ip, ping_count)
        assert status == True, f"Client failed to ping DUT"
        logger().info(" ********** Ping successful ********* ")
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        logger().info(f"*********RASPI_STA connected to DUT AP**********")
        logger().info(f"*********Validating the Sniffer Packet **********")

        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()

        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        logger().info("Initiating wireless de init")
        # deinit
        logger().info("Instead of reset need to add  wireless de init")
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.associated = True
        time.sleep(2)
        logger().info("Initiating wireless init")
        wifi_dut.interfaces.wifi.wireless_init(oper_mode=6, coex_mode=9)
        time.sleep(30)
        wifi_client.interfaces.wifi.join()
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")

        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        time.sleep(5)

        packet_filter1 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 8))'
        packet_filter2 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1  || ' \
                         f'eapol|| icmp))'
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("validating sniffer capture")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
            "Unable to find beacon frame  in Sniffer"
        logger().info(f"*********keep alive packets found in capture*********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2), \
            "Unable to find assoc req,assoc resp,eapol packets in Sniffer"
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
          clean_up.dut_recovery()
        clean_up.disconnect()
        raise e

###################################OPEN MODE######################
pytest.mark.wifi_client("raspi_wifi")
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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
# @pytest.mark.skip()
def test_DUT_APMode_store_config_C19451(wifi_sniffer, wifi_dut, wifi_client, channel):
    try:
        logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
        validation = True
        wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                          static_gateway=static_gateway)
        logger().info("********* configuring static ip to DUT *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info("********* configuring the sniffer with access point channel *********")
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_store_config_C19451')
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_dut.interfaces.wifi.start_ap(channel=channel)
        logger().info(" ********** Starting DUT as an AP ********* ")
        time.sleep(200)
        wifi_client.interfaces.wifi.join()
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        device_ip = wifi_client.interfaces.wifi.client_gateway_ip
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"********* Dut IP **********: {device_ip}")
        logger().info(f"********* Host IP *********: {host_ip}")
        logger().info(" ********** Starting ping ********* ")
        status = ping(device_ip, ping_count)
        assert status == True, f"Client failed to ping DUT"
        logger().info(" ********** Ping successful ********* ")
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        logger().info(f"*********RASPI_STA connected to DUT AP**********")
        logger().info(f"*********Validating the Sniffer Packet **********")

        # Save the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_save()

        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)

        logger().info("Initiating wireless de init")
        # deinit
        logger().info("Instead of reset need to add  wireless de init")
        wifi_dut.interfaces.wifi.reset_soft()
        wifi_dut.interfaces.wifi.associated = True
        time.sleep(2)
        logger().info("Initiating wireless init")
        wifi_dut.interfaces.wifi.wireless_init(oper_mode=6, coex_mode=9)
        time.sleep(20)
        # result = wifi_dut.interfaces.wifi.get_wireless_info()
        # assert wifi_dut.interfaces.wifi.ssid in result, "dut AP ssid not found in the get wireless info"
        wifi_client.interfaces.wifi.join()
        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")

        logger().info("Disable store configuration")
        # Enable the wireless configuration in the flash
        wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgDisable)
        time.sleep(5)

        packet_filter1 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 8))'
        packet_filter2 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1  || eapol|| icmp))'
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
            "Unable to find beacon frame with Region US in Sniffer"
        logger().info(f"*********keep alive packets found in capture*********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2), \
            "unable to find assoc request,assoc response or icmp packets in sniffer"
    except Exception as e:
        logger().info(f"Exception: {str(e)}")
        clean_up = cleanup_store_config(wifi_dut)
        if ("wlan_disconnect" in str(e)) or ("0xFFFFFFE2" in str(e)) or ("0xFFFFFFD5" in str(e)):
          clean_up.dut_recovery()
        clean_up.disconnect()
        raise e



########################SOFT RESET#################

pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": RS9116OperatingMode.AccessPoint,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.PSKSecurity,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Server | RS9116TCPIPFeatureBitMap.DHCPv4Client |
                          RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_APMode_softreset_aptosta_C19450(wifi_sniffer, wifi_dut, wifi_client, channel, wifi_access_point):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_softreset_aptosta_C19450')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    time.sleep(20)
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    rasp_mac = wifi_client.interfaces.wifi.get_mac_address()
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info(f"raspi_mac:{rasp_mac}")
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")

    logger().info("Initiating wireless de init")
    packet_filter1 = f'wlan.fc.type_subtype == 0x0008 && wlan.sa=={mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), \
        "Unable to find beacon frame from DUT  in Sniffer"

    # deinit
    logger().info("Instead of reset need to add  wireless de init")
    wifi_dut.interfaces.wifi.reset_soft()
    # wifi_dut.interfaces.wifi.associated = True
    time.sleep(2)
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_Trnms_rules_USregion_C19450')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    logger().info("Initiating wireless init")
    wifi_dut.interfaces.wifi.init(oper_mode=0, coex_mode=9)
    time.sleep(20)
    wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid, passphrase=wifi_access_point.interfaces.wifi.passphrase)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_as_client= wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f'dut ip is :{device_ip_as_client}')
    packet_filter2 = f'wlan.fc.type_subtype == 0x0004 && wlan.sa=={mac_address} && wlan.da==ff:ff:ff:ff:ff:ff'
    packet_filter3 = f'(wlan.addr=={mac_address})&&(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status == True, "DUT mac not found in DHCP packet"
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2),\
        "Unable to find probe req from dut in sniffer"
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3), \
        "Unable to find assoc req or resp packet in Sniffer"


######################################19449################################

pytest.mark.wifi_client("raspi_wifi")
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
        "security": "WPA2", "ssid": "DUT_AP", "passphrase": "test1234", "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "DUT_AP",
        "passphrase": "test1234",
    },
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'ap_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_softreset_statoap_C19449(wifi_sniffer, wifi_dut, wifi_client, channel,  wifi_access_point):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_softreset_statoap_C19449')
    logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
    wifi_dut.interfaces.wifi.join(ssid=wifi_access_point.interfaces.wifi.ssid, passphrase=wifi_access_point.interfaces.wifi.passphrase)
    ip_config = wifi_dut.interfaces.wifi.start_ip()
    device_ip_as_client= wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f'dut ip is :{device_ip_as_client}')
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    acces_point_ip = wifi_dut.interfaces.wifi.ip.gateway
    status = ping(acces_point_ip, ping_count)
    assert status == True, f"DUT failed to ping AP"
    packet_filter1 = f'wlan.fc.type_subtype == 0x0004 && wlan.sa=={mac_address} && wlan.da==ff:ff:ff:ff:ff:ff'
    packet_filter2 = f'(wlan.addr=={mac_address})&&(wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || eapol)'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    status = wifi_sniffer.interfaces.capture.get_dhcp_list(mac_address, decryption_key, ["dhcp"])
    logger().info(f'DHCP packet from DUT found: {status}')
    assert status == True, "DUT mac not found in DHCP packet"
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), \
        "Unable to find probe req from dut  in Sniffer"
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2), \
        "Unable to find assoc req or resp packet or eapol in Sniffer"
    # deinit
    logger().info("Initiating wireless de init")
    logger().info("Instead of reset need to add  wireless de init")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_Trnms_rules_USregion_C19449')
    logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
    logger().info("Initiating wireless init")
    wifi_dut.interfaces.wifi.init(oper_mode=6, coex_mode=9)
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_dut.interfaces.wifi.start_ap(channel= channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    time.sleep(20)
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    rasp_mac = wifi_client.interfaces.wifi.get_mac_address()
    logger().info(f"raspi_mac:{rasp_mac}")
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
    packet_filter3 = f'wlan.fc.type_subtype == 0x0008 && wlan.sa=={mac_address}'
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3),\
        "Unable to find beacon frame from DUT  in Sniffer"

#######19439######
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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_DUT_APMode_raspista_inactive_C19439(wifi_sniffer, wifi_dut, wifi_client, channel):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_raspista_inactive_C19439')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    logger().info("no data transmission between dut ap and raspi sta for 5 min")
    time.sleep(sleep_count)
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    packet_filter1 = f'((wlan.addr == {mac_address}) && (wlan.fc.type_subtype == 36 || wlan.fc.type_subtype == 12))'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"*********Validating the Sniffer Packet **********")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "Unable to find deauth or keep alive packet in Sniffer"
    logger().info(f"*********keep alive packets or deauth packets found in capture*********")


###############################19441########################

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
    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_DUT_APMode_fixed_datarate_C19441(wifi_sniffer, wifi_dut, wifi_client, channel, protocol, net_perf_client):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_fixed_datarate_C19441')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    logger().info(f"*********Initiating the disconnect from Raspi-STA **********")
    wifi_client.interfaces.wifi.leave()
    packet_filter1 = f'(wlan.addr == {mac_address}) && wlan.fc.type_subtype==40 && radiotap.datarate ==54'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"*********Validating the Sniffer Packet **********")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
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
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_ap_ht_caps")
def test_DUT_APMode_11n_htcaps_support_C19446(firmware_loader, wifi_sniffer, wifi_dut, wifi_client, channel, protocol, net_perf_client):
    logger().info("********* Currently Verifying  DUT_AP_Mode- Single_Client connection in US region*********")
    validation = True
    wifi_dut.interfaces.wifi.start_ip_in_static_mode(static_ip=static_ip, static_subnet=static_subnet,
                                      static_gateway=static_gateway)
    logger().info("********* configuring static ip to DUT *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info("********* configuring the sniffer with access point channel *********")
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_APMode_11n_htcaps_support_C19446')
    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_dut.interfaces.wifi.set_htcaps()
    wifi_dut.interfaces.wifi.start_ap(channel=channel)
    logger().info(" ********** Starting DUT as an AP ********* ")
    wifi_client.interfaces.wifi.join()
    logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
    device_ip = wifi_client.interfaces.wifi.client_gateway_ip
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"********* Dut IP **********: {device_ip}")
    logger().info(f"********* Host IP *********: {host_ip}")
    logger().info(" ********** Starting ping ********* ")
    status = ping(device_ip, ping_count)
    assert status == True, f"Client failed to ping DUT"
    logger().info(" ********** Ping successful ********* ")
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")
    # starting iperf server at raspi client
    logger().info("configured iperf server")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip,
                                                    protocol=protocol)
    logger().info("started iperf server")
    net_perf_client.interfaces.net_perf.start()

    # open socket and send traffic from dut
    logger().info("sending data from client dut")
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
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
    packet_filter1 = f'(wlan.addr == {mac_address}) && wlan.fc.type_subtype==8'
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(f"*********Validating the Sniffer Packet **********")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1),\
        "not found beacon from DUT "
    logger().info(f"*********beacon not found from DUT********")



