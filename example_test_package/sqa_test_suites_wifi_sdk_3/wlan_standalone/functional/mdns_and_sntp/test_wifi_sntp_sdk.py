import random
import string
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xPowerSaveModes, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode, Si91xJoinFeatureBitMap, Si91xPowerSaveProcedureTypes
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
import time

power_save = True

from utf.utf_config import UtfConfig


def logger():
    return get_logger(__name__)


"""
setup requirement:
        1. DUT(SiWG917) - 1
        2. Si-MB4002A -1
        3. Raspberry PI4 - 1
        4. Access Point(Third Party AP's) - 1
        5. NUC

    Author: Shaik Abdul Azeez
"""


class sntp_functionality(ThreadBase):
    """Thread to verify SNTP functionality."""
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def start_smtp(self):
        logger().info("**************** Creating SNTP Client Session in DUT ***************")
        self.wifi_dut.interfaces.wifi.sntp_client_start()
        time.sleep(10)  # Allow time for SNTP client to sync

        logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
        sntp_time, sntp_date = self.wifi_dut.interfaces.wifi.sntp_get_time_data()
        logger().info(f"**************** SNTP TIME **************** '{sntp_time}'")
        logger().info(f"**************** SNTP DATE **************** '{sntp_date}'\n")

    def run(self):
        try:
            logger().info("**************** Getting SNTP Server Information from DUT ***************")
            ip_version, sntp_method, sntp_server_address = self.wifi_dut.interfaces.wifi.sntp_get_server_info()
            logger().info(f"**************** SNTP SERVER IP VERSION: {ip_version}")
            logger().info(f"**************** SNTP SERVER ADDRESS: {sntp_server_address}")
            logger().info(f"**************** SNTP METHOD: {sntp_method}\n")

        except Exception as ex:
            logger().exception("Error in SNTP functionality thread.")
            raise ex


# Function to handle ping
class ping_functionality(ThreadBase):
    def __init__(self, wifi_dut, wifi_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client

    def run(self):
        try:
            ip_version = "ipv4"
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            logger().info(f"Initiate ping from DUT to third party wifi-client")
            self.wifi_dut.interfaces.wifi.ping(server_ip=host_ip, ip_version=ip_version, ping_size=64, num_ping_attempts=20)

        except Exception as ex:
            logger().exception("Error in ping functionality thread.")
            raise ex


def delta_between_sntp_packet():
    packet_filter = "Time delta from previous captured frame"
    count = 0
    time_diff_list = []

    filter_file = open(f'./reports/filter2_file.txt', 'r')
    line = filter_file.readlines()
    count1 = 0
    for x in line:
        count = count + 1
        if packet_filter in x:
            count1 += 1
            time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                'seconds', '')
            logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')

            if round(float(time_delta_from_previous_packet)) == 0:
                count1 -= 1
                continue
            else:
                time_diff_list.append(float(time_delta_from_previous_packet))
    filter_file.close()
    return time_diff_list


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_unicast_c19015(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                      sl_collections):
    """
    Verify SNTP init command with unicast method.
    """
    capture_filename = request.node.name
    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

    result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, retry_count=3,
                                                 associated=wifi_dut.interfaces.wifi.associated, power_save=power_save)
    dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")
    time.sleep(3)

    logger().info("**************** Creating SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_start()
    time.sleep(10)
    logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
    sntp_time, sntp_date = wifi_dut.interfaces.wifi.sntp_get_time_data()
    logger().info(f"**************** SNTP TIME ----> '{sntp_time}'")
    logger().info(f"**************** SNTP DATE ----> '{sntp_date}'\n")
    logger().info("**************** Getting SNTP Server Information from DUT ***************")
    ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
    logger().info(f"**************** SNTP SERVER {ip_version}")
    logger().info(f"**************** SNTP SERVER ADDRESS: {sntp_server_address}")
    logger().info(f"**************** SNTP {sntp_method}\n")
    logger().info("**************** Deleting SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_stop()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                           sniffer_filter, power_save=power_save)
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"DECRYPTION_KEY --> {decryption_key}")
    logger().info("SSL Packet Decryption is going to start, This may take some time")
    ntp_capture_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                            capture_filename, ap_bssid)['ntp']
    assert len(ntp_capture_list), (f"NTP packets are not captured or one of the 4-way handshake packets are not "
                                   f"captured in the sniffer capture")
    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == dut_ip):
            logger().info(f"************** SNTP response body received in the sniffer **************\n{ntp_pkt}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"channel": 1, "security": 'OPEN'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_keepalive_c19016(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                        sl_collections):
    """
    Verify NTP keep alive packets.
    """
    capture_filename = request.node.name
    time_delta = 30
    packet_filter2 = '    Flags: 0x1b, Leap Indicator: no warning, Version number: NTP Version 3, Mode: client'
    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

    result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, retry_count=3,
                                                 associated=wifi_dut.interfaces.wifi.associated,
                                                 power_save=power_save)
    dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")
    time.sleep(3)

    logger().info("**************** Creating SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_start()
    time.sleep(10)
    logger().info("**************** Getting SNTP Server Information from DUT ***************")
    ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
    logger().info(f"**************** SNTP SERVER {ip_version}")
    logger().info(f"**************** SNTP SERVER ADDRESS: {sntp_server_address}")
    logger().info(f"**************** SNTP {sntp_method}\n")
    logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
    sntp_time, sntp_date = wifi_dut.interfaces.wifi.sntp_get_time_data()
    logger().info(f"**************** SNTP TIME ----> '{sntp_time}'")
    logger().info(f"**************** SNTP DATE ----> '{sntp_date}'\n")
    time.sleep(180)
    logger().info("**************** Deleting SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_stop()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                    filter_name="ntp_keep_alive")

    packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                    filter_name="ntp_packet")

    packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                    da_addr=ap_bssid,
                                                                                    filter_name="power_mgmt_bit")

    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                              packet_filter2=packet_filter2)['packet_count'], \
        'Unable to find the ntp keep alive sniffer packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
        'Unable to find ntp sniffer packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
        'Unable to find the power save sniffer packets'

    logger().info("""******** Validation of time delta between keep-alive packets ********""")
    sntp_packets_time_delta_list = delta_between_sntp_packet()
    logger().info(f'SNTP packet time delta list after removing 0 = {sntp_packets_time_delta_list}')
    for time_diff in sntp_packets_time_delta_list:
        logger().info(int(time_diff))
        is_between = int(time_diff) in range(0, time_delta + 2)
        logger().info(is_between)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
def test_wifi_sdk_sntp_ludp_coexit_c19017(wifi_sniffer, wifi_dut, wifi_client, wifi_access_point, request,
                                          sniffer_filter, sl_collections, remote_socket):
    """
    Issue SNTP init command when ludp socket is opened at 123
    """
    capture_filename = request.node.name
    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

    result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, retry_count=3,
                                                 associated=wifi_dut.interfaces.wifi.associated, power_save=power_save)
    dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")

    data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    remote_socket.interfaces.socket.start_server(socket_type=1, port=123)
    server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)
    logger().info(f"Server IP is: {server_ip}")
    time.sleep(3)
    socket_id = wifi_dut.interfaces.wifi.socket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
    wifi_dut.interfaces.wifi.bind(socket_fd=socket_id, device_ip=result['device_ip'], ip_len=4, server_port=123)
    wifi_dut.interfaces.wifi.bsdSocketSendTo(socket_fd=socket_id, data=data, ip_addr=server_ip, ip_len=4, port=123)

    logger().info("**************** Creating SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_start(expected_status=SLStatus.SL_STATUS_SI91X_PORT_UNAVAILABLE)
    time.sleep(5)
    remote_socket.interfaces.socket.stop()
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.set_performance_profile(mode="high_performance")
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveDisabled, psp_type=0)
    wifi_dut.interfaces.wifi.inited = False
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                    da_addr=ap_bssid,
                                                                                    filter_name="power_mgmt_bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find the power save sniffer packets'


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_client_functionality_c37580(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                      sl_collections):
    """
    Command Type Response for SNTP Client Functionality.
    """
    capture_filename = request.node.name
    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    sl_collections.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"in harness power_save flag set to be : {sl_collections.power_save}")
    wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromPowerSave)
    result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, retry_count=3,
                                                associated=wifi_dut.interfaces.wifi.associated, power_save=False, )

    dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")
    time.sleep(3)

    logger().info(f"***** Enabling Powersave in DUT ******")
    wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency', dtim_aligned_type=0,
                                                     num_of_dtim_skip=0, listen_interval=700,
                                                     monitor_interval=50)
    wifi_dut.interfaces.wifi.enable_bt_power_save(psp_mode=Si91xPowerSaveModes.PowerSaveMode2,
                                                  psp_type=Si91xPowerSaveProcedureTypes.MaxPowerSave)

    logger().info("**************** Creating SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_start()
    time.sleep(10)
    logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
    sntp_time, sntp_date = wifi_dut.interfaces.wifi.sntp_get_time_data()
    logger().info(f"**************** SNTP TIME ----> '{sntp_time}'")
    logger().info(f"**************** SNTP DATE ----> '{sntp_date}'\n")
    logger().info("**************** Getting SNTP Server Information from DUT ***************")
    ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
    logger().info(f"**************** SNTP SERVER {ip_version}")
    logger().info(f"**************** SNTP SERVER ADDRESS: {sntp_server_address}")
    logger().info(f"**************** SNTP {sntp_method}\n")
    logger().info("**************** Deleting SNTP Client Session in DUT ***************")
    wifi_dut.interfaces.wifi.sntp_client_stop()

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                           sniffer_filter, power_save=power_save)
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"DECRYPTION_KEY --> {decryption_key}")
    logger().info("SSL Packet Decryption is going to start, This may take some time")
    ntp_capture_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                            capture_filename, ap_bssid)['ntp']
    assert len(ntp_capture_list), (f"NTP packets are not captured or one of the 4-way handshake packets are not "
                                   f"captured in the sniffer capture")
    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == dut_ip):
            logger().info(f"************** SNTP response body received in the sniffer **************\n{ntp_pkt}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_sntp_client_functionality_loop_c538048(wifi_sniffer, wifi_dut, wifi_access_point, request, sniffer_filter,
                                                   sl_collections):
    """
    Verify SNTP methods (sntp_start->gettime->get_time_date->get_server_info->sntp_client_stop)in loop.
    """
    capture_filename = request.node.name
    logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    # sl_collections.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    # logger().info(f"in harness power_save flag set to be : {sl_collections.power_save}")

    result = sl_collections.join_to_wifi_network(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, retry_count=3,
                                                 associated=wifi_dut.interfaces.wifi.associated, power_save=power_save, )

    dut_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {ap_bssid}")
    time.sleep(3)
    for count in range(10):
        logger().info(f"**************** Creating SNTP Client Session in DUT -'{count}'***************")
        wifi_dut.interfaces.wifi.sntp_client_start()
        time.sleep(10)
        logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
        sntp_time, sntp_date = wifi_dut.interfaces.wifi.sntp_get_time_data()
        logger().info(f">**************** SNTP TIME ----> '{sntp_time}'")
        logger().info(f"**************** SNTP DATE ----> '{sntp_date}'\n")
        logger().info("**************** Getting SNTP Server Information from DUT ***************")
        ip_version, sntp_method, sntp_server_address = wifi_dut.interfaces.wifi.sntp_get_server_info()
        logger().info(f"**************** SNTP SERVER {ip_version}")
        logger().info(f"**************** SNTP SERVER ADDRESS: {sntp_server_address}")
        logger().info(f"**************** SNTP {sntp_method}\n")
        logger().info("**************** Deleting SNTP Client Session in DUT ***************")
        wifi_dut.interfaces.wifi.sntp_client_stop()
        time.sleep(5)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                           sniffer_filter, power_save=power_save)
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"DECRYPTION_KEY --> {decryption_key}")
    logger().info("SSL Packet Decryption is going to start, This may take some time")
    ntp_capture_list = sl_collections.ssl_packet_decryption(wifi_sniffer, decryption_key, dut_mac_address, ["ntp"],
                                                            capture_filename, ap_bssid)['ntp']
    assert len(ntp_capture_list), (f"NTP packets are not captured or one of the 4-way handshake packets are not "
                                   f"captured in the sniffer capture")
    for ntp_pkt in ntp_capture_list:
        if (ntp_pkt[2] == sntp_server_address) and (ntp_pkt[3] == dut_ip):
            logger().info(f"************** SNTP response body received in the sniffer **************\n{ntp_pkt}")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_ping_and_sntp_functionality_threaded_c585584(wifi_access_point, wifi_dut, request, utf_constants, wifi_client,
                                                           wifi_sniffer, sniffer_filter, sl_collections):
    """Verify ping from DUT (ping Tx) in one thread and SNTP functionality in another thread."""

    test_case = request.node.name
    mode = "power_save_low_latency"
    ping_count = utf_constants.get("ping_count")

    try:
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point, power_save=True, retry_count=3,
                                            mode=mode, associated=wifi_dut.interfaces.wifi.associated, ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        # Create threads for SNTP and ping functionality
        sntp_thread = sntp_functionality(wifi_dut)
        ping_thread = ping_functionality(wifi_dut,wifi_client)
        sntp_thread.start_smtp()

        # Start threads
        sntp_thread.start()
        time.sleep(2)
        ping_thread.start()
        time.sleep(2)

        # Wait for both threads to complete
        sntp_thread.wait_for_exit()
        time.sleep(2)
        ping_thread.wait_for_exit()
        time.sleep(2)

        logger().info("**************** Deleting SNTP Client Session in DUT ***************")
        wifi_dut.interfaces.wifi.sntp_client_stop()

        logger().info("Disconnecting from AP...")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='power_mgmt_bit')

        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SNTPClient | Si91xTCPIPFeatureBitMap.DNSClient
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_wifi_sdk_verify_sntp_time_and_date_every_second_c192280(wifi_access_point, wifi_dut, request, utf_constants,
                                                                 wifi_client,
                                                                 wifi_sniffer, sniffer_filter, sl_collections):
    """Verify SNTP time and date every second for a set duration."""

    test_case = request.node.name
    mode = "power_save_low_latency"
    ping_count = utf_constants.get("ping_count")
    duration = 60  # Duration in seconds to verify SNTP data

    try:
        logger().info(" ====== configuring the Sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_case)

        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point=wifi_access_point, power_save=True,
                                            retry_count=3,
                                            mode=mode, associated=wifi_dut.interfaces.wifi.associated,
                                            ping_count=ping_count)

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")

        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")

        # Loop to verify SNTP time and date every second
        end_time = 60
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            logger().info("**************** Creating SNTP Client Session in DUT ***************")
            wifi_dut.interfaces.wifi.sntp_client_start()
            time.sleep(10)
            logger().info("**************** Getting SNTP Time and DATE from DUT ***************")
            sntp_time, sntp_date = wifi_dut.interfaces.wifi.sntp_get_time_data()
            logger().info(f"**************** SNTP TIME ----> '{sntp_time}'")
            logger().info(f"**************** SNTP DATE ----> '{sntp_date}'\n")
            time.sleep(5)
            logger().info("**************** Deleting SNTP Client Session in DUT ***************")
            wifi_dut.interfaces.wifi.sntp_client_stop()

        logger().info("Disconnecting from AP...")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr, filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'], \
            'Unable to find the power management save sniffer packets'

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)