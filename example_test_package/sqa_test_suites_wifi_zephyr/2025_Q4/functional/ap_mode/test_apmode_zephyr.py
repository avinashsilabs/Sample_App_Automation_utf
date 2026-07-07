import time
import pytest
from utf.interfaces.wifi import SecurityMode
from utf.utils import print_dict
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wifi_zephyr.devices.si91x import ZEPHYROperationalModes, ZephyrApConfigParams, ZEPHYRWiFiChannelBandwidth
from utf_wifi_zephyr.utils.sl_status import SLStatus
from threading import Thread
from datetime import datetime
from utf.interfaces.shell.ssh_shell import SSHShell

"""Test Author = Vinod.G
        1. Start the sniffer before connection
        2. Initiate connection from Wifi client(Raspberry)
        4. Initiate ping from the wifi client
        5. Disconnect the wifi client
        6. Stop the sniffer capture 
        7. Analysing all sniffer capture packets.
setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4 - 2 and more                                                           
        3. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def rts_cts_data_sequence_check(wifi_sniffer, dut_mac, ap_bssid, rts_threshold, test_case, data_len_check=True):
    snf_shell = wifi_sniffer.interfaces.capture.shell
    remote_cap_file = wifi_sniffer.interfaces.capture.remote_capture_file
    logger().info(f"capture file is:{remote_cap_file}")

    filter_files = "/tmp/filter_files"
    snf_shell(f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")
    rts_cts_file = f'{filter_files}/{test_case}_rts_cts.txt'
    data_filter = f'wlan.fc.type_subtype == 0x0028 && data.len > {rts_threshold}' if data_len_check else 'wlan.fc.type_subtype == 0x0028'
    rts_cts_filter = (f'tshark -r {remote_cap_file} -Tfields -e "frame.number" -e "wlan.fc.subtype" -Y '
                      f'"(wlan.ta == {dut_mac} && ({data_filter}) || (wlan.fc.type_subtype == 0x001b)) || '
                      f'(wlan.ra == {dut_mac} && wlan.fc.type_subtype == 0x001c)"')
    snf_shell(f'{rts_cts_filter} > {rts_cts_file}')

    if isinstance(snf_shell, SSHShell):
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
            time_stamp = datetime.fromtimestamp(time.time()).strftime('%m_%d_%Y-%H_%M_%S')
            out_file = f"./reports/{test_case}_rts_cts_{time_stamp}.txt"
            sftp_main.get(rts_cts_file, out_file)
            sftp_main.close()

    logger().info("************ Checking RTS, CTS, DATA Packets Sequence in Sniffer ************")
    frames_dict = {}
    with open(out_file, "r") as fd:
        for line in fd.readlines():
            frames_dict[line.split()[0]] = line.split()[1]

    status = False
    rts = cts = 0
    for frame_num, frame_type in frames_dict.items():
        if frame_type == '11':
            rts = int(frame_num)
        elif frame_type == '12' and rts:
            cts = int(frame_num)
        elif frame_type == '8' and cts:
            data = int(frame_num)
            message = (f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))} and "
                       f"data length greater than rts_threshold value '{rts_threshold}'")
            if not data_len_check:
                message = f"Found Sequence [RTS--->CTS--->DATA] with frame numbers {list((rts, cts, data))}"
            logger().info(message)
            rts = cts = 0
            status = True
        else:
            rts = cts = 0
    return status


class FilterPacket:
    def __init__(self, open_file=True, line=None, IE=None):
        """
        Class for parsing sniffer capture to get beacon interval and dtim period.
        """
        self.open_file = open_file
        self.line = line
        self.IE = IE

        if self.open_file:
            filter_file = open(f'./reports/filter2_file.txt', 'r')
            self.line = filter_file.readlines()

    def filter_ies(self, packet_filter):
        logger().info(f"**********************")
        for self.IE in self.line:
            if packet_filter in self.IE:
                break
        return self.IE

    def get_ssid(self):
        packet_filter = "SSID:"
        self.IE = self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_hidden_ssid(self):
        packet_filter = "Tag: SSID parameter set:"
        self.IE = self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_supported_rates(self):
        packet_filter = "Supported Rates:"
        self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_channel_info(self):
        packet_filter = "Current Channel:"
        self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_country_info(self):
        packet_filter = "Code:"
        self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_rsn_info(self):
        packet_filter = "RSN Version:"
        self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_tim_info(self):
        packet_filter = "DTIM period:"
        self.filter_ies(packet_filter=packet_filter)
        return self.IE

    def get_erp_info(self):
        packet_filter = "Tag Number: ERP"
        self.filter_ies(packet_filter=packet_filter)
        return self.IE


class ApModeClientConnections(ThreadBase):
    def __init__(self, wifi_dut, wifi_clients, wifi_sniffer,
                 zephyr_wifi_collections, utf_constants, net_perf_client=None, protocol=None, testcase_no=None,
                 capture_filename=None,
                 dtim_period=None, beacon=None, traffic_type=None, leave=True, enable_data_rate=False,
                 sniffer_stop=False, htcaps_enable=None, client_limit=0, disable_dhcp_server=0):
        self.wifi_dut = wifi_dut
        self.wifi_clients = wifi_clients
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_sniffer = wifi_sniffer
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.utf_constants = utf_constants
        self.capture_filename = capture_filename
        self.testcase_no = testcase_no
        self.dtim_period = dtim_period
        self.beacon = beacon
        self.traffic_type = traffic_type
        self.leave = leave
        self.enable_data_rate = enable_data_rate
        self.sniffer_stop = sniffer_stop
        self.htcaps_enable = htcaps_enable
        self.wifi_dut.interfaces.wifi.mode_change()
        self.client_limit = client_limit
        self.disable_dhcp_server = disable_dhcp_server

    def run(self):
        if self.testcase_no == 19454 or 19432:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 4

        if self.testcase_no == 551267 or self.testcase_no == 793715:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1

        if self.testcase_no == 19465 or self.testcase_no == 19441:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1

        if self.testcase_no == 37595:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "1"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1

        if self.testcase_no == 19484:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 2

        if self.testcase_no == 19447:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "11"
            self.dtim_count = "4"
            self.beacon_interval = self.beacon
            self.no_of_clients = 1
            self.htcaps_enable = 1

        if self.testcase_no == 19456:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "13"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 4

        if self.testcase_no == 477826:
            self.ssid = "SILABS_AP_MODE"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.channel = "13"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.no_of_clients = 1

        if self.testcase_no == 19444:
            self.ssid = "SILABS_AP_C19444"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.beacon_interval = "100"
            self.channel = "11"
            self.dtim_count = self.dtim_period
            self.no_of_clients = 1

        if self.testcase_no == 551265:
            self.ssid = "SILABS_AP_C551265"
            self.security = "WPA"
            self.password = "Automation@123"
            self.beacon_interval = "500"
            self.channel = "13"
            self.dtim_count = 3
            self.no_of_clients = 1

        if self.testcase_no == 551266:
            self.ssid = "SILABS_AP_C551266"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.beacon_interval = "500"
            self.channel = "14"
            self.dtim_count = 3
            self.no_of_clients = 1

        if self.testcase_no == 19443:
            self.ssid = "SILABS_AP_C19443"
            self.security = "WPA2"
            self.password = "12345678"
            self.dtim_count = "1"
            self.beacon_interval = self.beacon
            self.channel = "11"
            self.no_of_clients = 1

        if self.testcase_no == 662092:
            self.ssid = "SILABS_AP"
            self.security = "WPA2"
            self.password = "Automation@123"
            self.dtim_count = "1"
            self.beacon_interval = "100"
            self.channel = "13"
            self.no_of_clients = 2

        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)
        if self.client_limit == 4:
            self.wifi_dut.interfaces.wifi.wifi_ap_config()
        if self.client_limit == 1:
            self.wifi_dut.interfaces.wifi.wifi_ap_config(max_num_sta=1)
        ping_count = self.utf_constants.get("ping_count")
        if not self.disable_dhcp_server:
            self.zephyr_wifi_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip="192.168.100.76",
                                                                    static_subnet="255.255.255.0")
        if self.testcase_no == 19441:
            self.dut_addr_dict = self.zephyr_wifi_collections.ap_mode_clients_connection(self.wifi_dut,
                                                                                         self.wifi_clients,
                                                                                         channel=self.channel,
                                                                                         ssid=self.ssid,
                                                                                         security=self.security,
                                                                                         password=self.password,
                                                                                         dtim_count=self.dtim_count,
                                                                                         beacon_interval=self.beacon_interval,
                                                                                         ht_caps=self.htcaps_enable,
                                                                                         ping_count=ping_count,
                                                                                         no_of_clients=self.no_of_clients,
                                                                                         leave=self.leave,

                                                                                         enable_data_rate=self.enable_data_rate,
                                                                                         data_rate="24Mbps")
        else:
            logger().info("***** Other than 19441 case *** ")
            self.dut_addr_dict = self.zephyr_wifi_collections.ap_mode_clients_connection(self.wifi_dut,
                                                                                         self.wifi_clients,
                                                                                         channel=self.channel,
                                                                                         ssid=self.ssid,
                                                                                         security=self.security,
                                                                                         password=self.password,
                                                                                         dtim_count=self.dtim_count,
                                                                                         beacon_interval=self.beacon_interval,
                                                                                         ht_caps=self.htcaps_enable,
                                                                                         ping_count=ping_count,
                                                                                         no_of_clients=self.no_of_clients,
                                                                                         leave=self.leave,
                                                                                         enable_data_rate=self.enable_data_rate
                                                                                         )
        if self.traffic_type == "Tx":
            logger().info(f"***** starting iperf ******")
            self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.dut_addr_dict['client_ip'],
                                                                 device_ip=self.dut_addr_dict['dut_ip'],
                                                                 protocol=self.protocol)
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"***** send traffic  ******")
            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                local_ip=self.dut_addr_dict['dut_ip'],
                                                remote_ip=self.dut_addr_dict['client_ip'],
                                                remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                size=1460, ttl=30, throughput_type=1, qos=0, async_socket=1)
            logger().info(f"***** get and print throughput ******")
            tp = self.net_perf_client.interfaces.net_perf.process_output()
            assert tp, "failed to get throughput..."
            logger().info("data transfer is successful")
            time.sleep(5)
        if self.traffic_type == "Rx":
            if self.protocol == "UDP":
                transfer_type = 2
                protocol = 17
                size = 1470
                throughput_type = 4
                bandwidth = "68M"
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.dut_addr_dict['client_ip'],
                                                                     device_ip=self.dut_addr_dict['dut_ip'],
                                                                     protocol=self.protocol, bandwidth=bandwidth)
            else:
                transfer_type = 1
                protocol = 6
                size = 1460
                throughput_type = 3
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.dut_addr_dict['client_ip'],
                                                                     device_ip=self.dut_addr_dict['dut_ip'],
                                                                     protocol=self.protocol)

            self.net_perf_client.interfaces.net_perf.start()

            logger().info("receiving data from Host")
            self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=transfer_type, protocol=protocol,
                                                local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                local_ip=self.dut_addr_dict['dut_ip'],
                                                remote_ip=self.dut_addr_dict['client_ip'],
                                                remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                size=size, ttl=30, throughput_type=throughput_type, qos=0)

            logger().info("data received is successful")
            time.sleep(3)
        if self.sniffer_stop:
            logger().info("Stop sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_traffic_btwn_two_clients(self, net_perf_server, net_perf_client, server_ip, client_ip, protocol,
                                     iperf_time=30):
        logger().info(f"********************** Starting Iperf Server on {net_perf_server.name} **********************")
        net_perf_server.interfaces.net_perf.init_server(protocol=protocol, host_ip=client_ip,
                                                        device_ip=server_ip, time_out=iperf_time, version=4)
        net_perf_server.interfaces.net_perf.start()
        server_port = net_perf_server.interfaces.net_perf.server_port
        time.sleep(5)
        logger().info(f"********************** Starting Iperf Client on {net_perf_client.name} **********************")
        net_perf_client.interfaces.net_perf.init_client(host_ip=server_ip, device_ip=client_ip,
                                                        protocol=protocol, time_out=iperf_time, version=4)
        client_port = net_perf_client.interfaces.net_perf.client_port
        args = net_perf_client.interfaces.net_perf.executable_arguments
        args[args.index(str(client_port))] = str(server_port)
        net_perf_client.interfaces.net_perf.start()
        time.sleep(iperf_time + 10)
        logger().info("Printing Throughput")
        tp = net_perf_server.interfaces.net_perf.process_output()
        time.sleep(3)
        assert tp is not None, "Throughput not found"
        logger().info("data transfer is successful")
        self.print_throughput(tp)
        net_perf_client.interfaces.net_perf.iperf_process.stop(5)


class IperfThread(ThreadBase):

    def __init__(self, wifi_dut=None, wifi_access_point=None, sl_collections=None, test_name=None, wifi_client=None,
                 test_id=None, traffic_type=None, protocol=None, net_perf_client=None, timeout=60,
                 device_ip=None, remote_ip=None, ip_version=4, async_socket=0):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.ip_version = ip_version
        self.device_ip = device_ip
        self.remote_ip = remote_ip
        self.async_socket = async_socket

    def run_traffic(self):
        logger().info(f"initiating traffic in {self.protocol} with type {self.traffic_type}")
        self.sl_collections.run_traffic(
            wifi_dut=self.wifi_dut,
            net_perf_client=self.net_perf_client,
            protocol=self.protocol,
            device_ip=self.device_ip,
            host_ip=self.remote_ip,
            timeout=self.timeout,
            traffic_type=self.traffic_type,
            ip_version=self.ip_version,
            buffer_size_tcp=1380,
            buffer_size_udp=1390,
            async_socket=self.async_socket
        )

    def run(self):
        self.run_traffic()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('C551262')
def test_wifi_zephyr_dutap_2_4_channel_in_5_ghz_band_C551262(wifi_sniffer, wifi_dut,
                                                             utf_constants, zephyr_wifi_collections, wifi_client,
                                                             sniffer_filter
                                                             ):
    """verify whether DUT is able to send Error or not when configuring 40MHZ bandwidth"""
    wifi_dut.interfaces.wifi.mode_change()
    zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0")
    try:
        logger().info(" ********** Starting DUT as an AP with channel as 36 ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", channel=1, band=1,
                                          expected_status=SLStatus.SL_STATUS_FAIL)

        logger().info(
            "DUT throws error when trying to configure the AP in channel 1 when 5GHZ band is selected which is expected behavior")

    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "OPEN",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('C19436')
def test_wifi_zephyr_dutap_verify_beacon_format_c19436(wifi_sniffer, wifi_dut, wifi_access_point,
                                                       utf_constants, zephyr_wifi_collections, wifi_clients,
                                                       sniffer_filter,
                                                       request):
    """Verify beacon format sent by APUT"""
    try:
        beacon = 100
        capture_filename = request.node.name
        packet_filter2 = "    Type/Subtype: Beacon (0x0008)"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             testcase_no=19465, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        dut_mac_address = ap_dut_obj.dut_addr_dict['dut_mac_address']
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # logger().info(f"*******{packet_filter1}**********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2), "not found beacon from DUT "
        logger().info('********** Validating Beacon interval **********')
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            radio_ch=ap_dut_obj.channel,
            beacon=beacon, filter_name="beacon_ap_mode_beacon_interval")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find beacon_ap_mode_beacon_interval packet in sniffer'
        IE_obj = FilterPacket(open_file=True)
        ssid = IE_obj.get_ssid()
        logger().info(f"*******{ssid}*********")
        supported_rates = IE_obj.get_supported_rates()
        logger().info(f"*******{supported_rates}*********")
        channel = IE_obj.get_channel_info()
        logger().info(f"*******{channel}******")
        country_code = IE_obj.get_country_info()
        logger().info(f"*******{country_code}******")
        dtim_period = IE_obj.get_tim_info()
        logger().info(f"*******{dtim_period}******")
        ERP_info = IE_obj.get_erp_info()
        logger().info(f"*******{ERP_info}******")
        RSN_info = IE_obj.get_rsn_info()
        logger().info(f"*******{RSN_info}******")
    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@1234",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.test_src_map_id('C19437')
def test_wifi_zephyr_apmode_connectivity_with_wrong_psk_cli_c19437(wifi_sniffer, sniffer_filter,
                                                                   utf_constants, wifi_dut, wifi_clients,
                                                                   sl_collections, request):
    """ Verify whether DUT is sending disassociation frame after 4 way handshake fail when third party STA is trying to connect with wrong PSK"""
    try:
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                             utf_constants,
                                             testcase_no=19465, capture_filename=capture_filename)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            wlan_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name="disassociation")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find disassociation packet in sniffer'
    except:
        logger().info(f"connectivity fails as PSK is given wrong -->Expected")
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('C996274')
def test_wifi_zephyr_client_limit_10_c996274(wifi_sniffer, wifi_dut,
                                             utf_constants, zephyr_wifi_collections, wifi_clients,
                                             sniffer_filter, request):
    """Check whether wifi.ap_config sends error when max client limit is set to 10"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        wifi_dut.interfaces.wifi.wifi_ap_config(max_num_sta=10, expected_status=SLStatus.SL_STATUS_FAIL)
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@1234", channel=11)

        logger().info("Stop Sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996275')
def test_wifi_zephyr_ap_functionality_when_bandwidth_20mhz_selected_c996275(wifi_sniffer, wifi_dut,
                                                                            utf_constants, zephyr_wifi_collections,
                                                                            wifi_client,
                                                                            sniffer_filter, request):
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11,
                                          bandwidth=ZEPHYRWiFiChannelBandwidth.WIFI_FREQ_BANDWIDTH_20MHZ)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123",
                                         country="US")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('c19447')
def test_wifi_zephyr_dut_apmode_11n_htcaps_support_c19447(wifi_sniffer, wifi_dut, channel, protocol,
                                                          zephyr_wifi_collections, wifi_clients, utf_constants,
                                                          sniffer_filter,
                                                          net_perf_client, request):
    """HT CAP Functionality ,High through put capabilities in AP mode"""
    try:
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             net_perf_client=net_perf_client, protocol=protocol,
                                             testcase_no=19447, sniffer_stop=False, leave=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        zephyr_wifi_collections.run_traffic(wifi_dut=wifi_dut, net_perf_client=net_perf_client,
                                            protocol=protocol, device_ip=ap_dut_obj.dut_addr_dict['dut_ip'],
                                            host_ip=ap_dut_obj.dut_addr_dict['client_ip'], timeout=40,
                                            traffic_type="TX")
        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name='beacon')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon in Sniffer'
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address']
            , filter_name="beacon_HT_capability")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Sniffer: Unable to find htcaps_IES packet in sniffer'

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
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
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.test_src_map_id('C19449')
def test_wifi_zephyr_dut_soft_reset_sta_to_ap_c19449(wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                     wifi_access_point,
                                                     utf_constants, zephyr_wifi_collections, sniffer_filter, request):
    """Soft Reset functionality when dUT moving from STA mode to AP mode"""
    try:
        capture_filename = request.node.name
        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename + "sta")
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        dut_addr = zephyr_wifi_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                                wifi_access_point=wifi_access_point,
                                                                power_save=False,
                                                                associated=wifi_dut.interfaces.wifi.associated,
                                                                retry_count=3, ping_after_power_save=False,
                                                                ping_count=ping_count)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_addr['dut_mac_address'],
                                                        ap_bssid, sniffer_filter,
                                                        power_save=False)
        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            ta_addr=dut_addr['dut_mac_address'],
            ra_addr=ap_bssid,
            filter_name='data_packets')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
            'Sniffer: Unable to find data_packets in sniffer'

        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename + "ap",
                                             testcase_no=19465, sniffer_stop=True)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        zephyr_wifi_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                      dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                      rasp_mac_address=ap_dut_obj.dut_addr_dict['rasp_mac_address'])

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 0,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.test_src_map_id('C37589')
def test_wifi_zephyr_dut_ap_verify_channel_0_c37589(wifi_dut,
                                                    utf_constants, zephyr_wifi_collections, wifi_client, sniffer_filter,
                                                    net_perf_client, protocol):
    """Verify AP functionality in ACS (CH as 0) mode in 2G"""
    try:
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=0)
        logger().info("DUT as soft AP configuring in auto channel")
        time.sleep(12)
        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)
        channel = int(channel)

        # assert channel == 0, "Soft AP is not configured in auto channel"

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        zephyr_wifi_collections.run_traffic(wifi_dut, net_perf_client, protocol, dut_ip,
                                            client_ip, timeout=60,
                                            traffic_type="RX")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "Open",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c586186')
def test_wifi_zephyr_sta_association_to_aput_hidden_ssid_open_security_c586186(wifi_sniffer, wifi_dut,
                                                                               utf_constants, zephyr_wifi_collections,
                                                                               wifi_client,
                                                                               sniffer_filter, request):
    """Check the 3rd party STA Association to APUT with Hidden SSID in open security mode"""
    try:
        capture_filename = request.node.name
        packet_filter2 = "    Type/Subtype: Beacon (0x0008)"

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="Open", psk="Automation@123", channel=11,
                                          ignore_broadcast_ssid=1)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open, passphrase="Automation@123",
                                         country="US", scan_ssid=1)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # logger().info(f"*******{packet_filter1}**********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2), "not found beacon from DUT "
        logger().info('********** Validating Beacon interval **********')
        IE_obj = FilterPacket(open_file=True)
        ssid = IE_obj.get_hidden_ssid()
        logger().info(f"*******{ssid}*********")
        hidden_ssid = 0
        if "Wildcard SSID" in ssid:
            logger().info(f"found the hidden ssid")
            hidden_ssid = 1
        assert hidden_ssid

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c535822')
def test_wifi_zephyr_sta_association_to_aput_hidden_ssid_wpa2_security_c535822(wifi_sniffer, wifi_dut,
                                                                               utf_constants, zephyr_wifi_collections,
                                                                               wifi_client,
                                                                               sniffer_filter, request):
    """Check the 3rd party STA Association to APUT with Hidden SSID Mode in WPA2 security mode"""
    try:
        capture_filename = request.node.name
        packet_filter2 = "    Type/Subtype: Beacon (0x0008)"

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11,
                                          ignore_broadcast_ssid=1)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123",
                                         country="US", scan_ssid=1)
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype==8)'
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # logger().info(f"*******{packet_filter1}**********")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                                  packet_filter2=packet_filter2), "not found beacon from DUT "
        logger().info('********** Validating Beacon interval **********')
        IE_obj = FilterPacket(open_file=True)
        ssid = IE_obj.get_hidden_ssid()
        logger().info(f"*******{ssid}*********")
        hidden_ssid = 0
        if "Wildcard SSID" in ssid:
            logger().info(f"found the hidden ssid")
            hidden_ssid = 1
        assert hidden_ssid

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996277')
def test_wifi_zephyr_dutap_bandwidth_40mhz_c996277(wifi_sniffer, wifi_dut,
                                                   utf_constants, zephyr_wifi_collections, wifi_client,
                                                   sniffer_filter
                                                   ):
    """verify whether DUT is able to send Error or not when configuring 40MHZ bandwidth"""
    wifi_dut.interfaces.wifi.mode_change()
    zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0")
    try:
        logger().info(" ********** Starting DUT as an AP with channel as 36 ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", channel=1,
                                          bandwidth=ZEPHYRWiFiChannelBandwidth.WIFI_FREQ_BANDWIDTH_40MHZ,
                                          expected_status=SLStatus.SL_STATUS_FAIL)

        logger().info(
            "DUT throws error when trying to configure the AP in channel 1 with bandwidth 40MHZ which is expected behavior")

    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.test_src_map_id('c996278')
def test_wifi_zephyr_dut_apmode_disconnect_client_c996278(wifi_sniffer, wifi_dut, channel,
                                                          zephyr_wifi_collections, wifi_clients,
                                                          utf_constants,
                                                          sniffer_filter,
                                                          request
                                                          ):
    """Disconnect connected STA using the CLI MAC address"""
    try:
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             testcase_no=19447, sniffer_stop=False, leave=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        ping_count = 5
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")

        client_mac = wifi_clients[0].interfaces.wifi.get_mac_address()
        wifi_dut.interfaces.wifi.disconnect_client(sta_mac=client_mac)
        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c {ping_count} {dut_ip}")
        assert rc == 1, f"RASPI-STA able to ping to DUT even after disconnected"

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 36,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c19435')
def test_wifi_zephyr_dut_ap_verify_5g_channel_in_2_4_ghz_c19435(wifi_sniffer, wifi_dut,
                                                                utf_constants, zephyr_wifi_collections, wifi_client,
                                                                sniffer_filter
                                                                ):
    """verify whether DUT is able to send Error or not when configuring 5GHZ channels in 2.4G band"""
    wifi_dut.interfaces.wifi.mode_change()
    zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                       static_subnet="255.255.255.0")
    try:
        logger().info(" ********** Starting DUT as an AP with channel as 36 ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", channel=36, expected_status=SLStatus.SL_STATUS_FAIL)

        logger().info("DUT throws error when trying to configure the AP in channel 36 which is expected behavior")

    except Exception as error:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [1, 6, 11])
@pytest.mark.test_src_map_id('c996279')
def test_wifi_zephyr_sta_different_channels_aput_c551263(wifi_sniffer, wifi_dut,
                                                         zephyr_wifi_collections, utf_constants, wifi_client,
                                                         sniffer_filter,
                                                         channel, request):
    """Configure APUT in 2.4Ghz in the following channels 1,6,11 and verify connectivity with the 3rd party STAs"""
    # Channel 14 is not supported by raspberry
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=channel)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2, passphrase="Automation@123",
                                         country="US")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
def test_wifi_zephyr_dut_apmode_disconnect_client_when_client_limit_1_c996279(wifi_sniffer, wifi_dut, channel,
                                                                              zephyr_wifi_collections, wifi_clients,
                                                                              utf_constants,
                                                                              sniffer_filter,
                                                                              request
                                                                              ):
    """ Disconnect the connected STA when max client limit is set to 1"""

    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        wifi_dut.interfaces.wifi.wifi_ap_config(max_num_sta=1)
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_clients[0].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                             passphrase="Automation@123",
                                             country="US")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_clients[0].interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_clients[0].interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        wifi_dut.interfaces.wifi.disconnect_client(sta_mac=rasp_mac_address)

        logger().info("Stop Sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "OPEN",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c19176')
def test_wifi_zephyr_dut_apmode_get_wireless_stats_security_open_c19176(wifi_sniffer, wifi_dut,
                                                                        utf_constants, zephyr_wifi_collections,
                                                                        wifi_client,
                                                                        sniffer_filter, request):
    """ Check whether the DUT is able to give stats in open mode"""
    try:
        capture_filename = request.node.name

        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="Open", psk="Automation@123", channel=11)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open, passphrase="Automation@123")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)
        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == "SILABS_AP_MODE", "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert int(channel) == 11, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 0, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert bssid.lower() == dut_mac_address.lower(), "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(
            dtim_period) == 3, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(
            beacon_interval) == 100, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(iface_mode) == 2, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "
        assert int(link_mode) == 4, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "

        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.test_src_map_id('c564146')
def test_wifi_zephyr_dut_apmode_get_wireless_config_security_wpa2_c564146(wifi_sniffer, wifi_dut, channel,
                                                                          zephyr_wifi_collections, wifi_clients,
                                                                          utf_constants,
                                                                          sniffer_filter,
                                                                          request
                                                                          ):
    """Check stats info in AP mode"""
    try:
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,

                                             testcase_no=19447, sniffer_stop=False, leave=False)
        bssid_dut = wifi_dut.interfaces.wifi.get_mac_address()
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
            timeout=15)

        assert int(state) == 9, "DUT is not in connected state"
        assert ssid == ap_dut_obj.ssid, "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
        assert channel == ap_dut_obj.channel, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(security) == 1, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert bssid.lower() == bssid_dut.lower(), "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong"
        assert int(
            dtim_period) == 3, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(
            beacon_interval) == 100, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
        assert int(iface_mode) == 2, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "
        assert int(link_mode) == 4, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "OPEN",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c689175')
def test_wifi_zephyr_dut_apmode_get_wireless_config_while_sta_conn_disconnect_multiple_times_c689175(wifi_sniffer,
                                                                                                     wifi_dut,
                                                                                                     utf_constants,
                                                                                                     zephyr_wifi_collections,
                                                                                                     wifi_client,
                                                                                                     sniffer_filter,
                                                                                                     request):
    """Run stats command multiple times when STA connect and disconnect to AP multiple times"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="Open", psk="Automation@123", channel=11)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        def run_wireless_config_stats(wifi_dut, iteration_count):
            for count in range(0, iteration_count):
                time.sleep(1)
                state, ssid, bssid, band, channel, iface_mode, link_mode, wpa3_ent_type, security, mfp, rssi, dtim_period, beacon_interval, twt_capable, current_phy_tx_rate = wifi_dut.interfaces.wifi.get_wifi_operational_stats(
                    timeout=15)
                assert int(state) == 9, "DUT is not in connected state"
                assert ssid == "SILABS_AP_MODE", "SSID details retrieved using WIFI_IFACE_STATUS API are wrong"
                assert int(channel) == 11, "Channel info retrieved using WIFI_IFACE_STATUS API is wrong"
                assert int(security) == 0, "Security info retrieved using WIFI_IFACE_STATUS API is wrong"
                assert bssid.lower() == dut_mac_address.lower(), "BSSID info retrieved using WIFI_IFACE_STATUS API is wrong"
                assert int(
                    dtim_period) == 3, "DTIM period set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
                assert int(
                    beacon_interval) == 100, "Beacon interval set in AP, and retrieved using WIFI_IFACE_STATUS API is not same"
                assert int(
                    iface_mode) == 2, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "
                assert int(
                    link_mode) == 4, "iface_mode retrieved using WIFI_IFACE_STATUS API is not valid. Expected is 2 "

        iteration_count = 100
        thread = Thread(target=run_wireless_config_stats, args=(wifi_dut, iteration_count), )
        thread.start()

        for count in range(0, 3):
            logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
            wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open,
                                             passphrase="Automation@123")
            time.sleep(2)
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"********* Dut IP **********: {dut_ip}")
            rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
            logger().info(f"raspi_mac: {rasp_mac_address}")
            client_ip = wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Client_ip: {client_ip}")
            time.sleep(2)
            logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
            rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
                f"sudo ping -c {5} {dut_ip}")
            assert rc == 0, f"RASPI-STA failed to ping DUT"
            logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
            logger().info(f'RASPI-STA Disconnecting from DUT-AP')
            wifi_client.interfaces.wifi.leave()
            time.sleep(2)


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996281')
def test_wifi_zephyr_sta_association_to_aput_in_wpa_security_c996281(wifi_sniffer, wifi_dut,
                                                                     utf_constants, zephyr_wifi_collections,
                                                                     wifi_client,
                                                                     sniffer_filter, request):
    """Check connectivity in TKIP mode"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA", psk="Automation@123", channel=11,
                                          )

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA, passphrase="Automation@123",
                                         country="US")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.test_src_map_id('c996282')
def test_wifi_zephyr_dut_apmode_disable_functionality_c996282(wifi_sniffer, wifi_dut, channel,
                                                              zephyr_wifi_collections, wifi_clients,
                                                              utf_constants,
                                                              sniffer_filter,
                                                              request
                                                              ):
    """Verify AP mode disable functionality"""
    try:
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,

                                             testcase_no=19447, sniffer_stop=False, leave=False)
        bssid_dut = wifi_dut.interfaces.wifi.get_mac_address()
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        time.sleep(3)

        wifi_dut.interfaces.wifi.wifi_ap_disable()

        for i in range(0, 1):
            logger().info(f'RASPI-STA{i + 1} Disconnecting from DUT-AP')
            wifi_clients[i].interfaces.wifi.leave()

        try:
            wifi_clients[0].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                                 passphrase="Automation@123",
                                                 country="US")
        except:
            logger().info(
                f"RASPI-STA unable to connect to AP after ap disable which is expected behavior")
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "OPEN",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996262')
def test_wifi_zephyr_dutap_rts_threshold_set_to_0_c996262(wifi_dut, wifi_sniffer, utf_constants,
                                                          zephyr_wifi_collections,
                                                          wifi_client, sniffer_filter, net_perf_client, request):
    """ Verify whether DUT is sending RTS packets for every data packet if we configure RTS Threshold as '0'"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="OPEN", psk="Automation@123", channel=11)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_client.interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.Open, passphrase="Automation@123")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_client.interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        set_rts_threshold_value = wifi_dut.interfaces.wifi.wifi_rts_threshold(threshold_value=0)
        get_rts_threhold_value = wifi_dut.interfaces.wifi.wifi_get_rts_threshold()

        assert set_rts_threshold_value == get_rts_threhold_value, "The RTS threshold value set via wifi_rts_threshold does not match the value returned by wifi_get_rts_threshold"

        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")
        logger().info(f'RASPI-STA Disconnecting from DUT-AP')
        wifi_client.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("\n\nValidating RTS,CTS,DATA Packets in sniffer capture")
        status = rts_cts_data_sequence_check(wifi_sniffer, dut_mac_address, rasp_mac_address, rts_threshold=0,
                                             test_case="test_C19512")
        assert status, "Unable to find sequence RTS--->CTS--->DATA packets with data length more than rts_threshold value"



    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
        "channel": 1,
        "interface": "wlan0",
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996267')
def test_neg_wifi_zephyr_ap_us_region_channel_13_c996267(wifi_dut, zephyr_wifi_collections):
    """Verify DUT functionality when configuring in channel 13, and region is set to US"""
    try:
        wifi_dut.interfaces.wifi.mode_change()
        set_region_code = "US"
        wifi_dut.interfaces.wifi.wifi_reg_domain(country_code=set_region_code)
        region_code = wifi_dut.interfaces.wifi.wifi_get_reg_domain()
        assert set_region_code == region_code, "region code set, and the region code received using wifi_get_reg_domain is not same"
        logger().info("Initiating scan from dut...")
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=13,
                                          expected_status=SLStatus.SL_STATUS_FAIL)

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996273')
def test_wifi_zephyr_dutap_max_client_limit_4_c996273(wifi_sniffer, wifi_dut, wifi_clients,
                                                      zephyr_wifi_collections, utf_constants,
                                                      sniffer_filter, request):
    """AP functionality, If many clients are connected & disconnected multiple times"""
    try:
        max_client_limit = 4
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             testcase_no=max_client_limit, client_limit=max_client_limit)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(4):
            zephyr_wifi_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                          dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                          rasp_mac_address=wifi_clients[
                                                              i].interfaces.wifi.get_mac_address())

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },

    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996272')
def test_wifi_zephyr_client_limit_1_c996272(wifi_sniffer, wifi_dut,
                                            utf_constants, zephyr_wifi_collections, wifi_clients,
                                            sniffer_filter, request):
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        wifi_dut.interfaces.wifi.wifi_ap_config(max_num_sta=1)
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)

        logger().info(" ********** Raspberry pi Client connecting to DUT-AP ********* ")
        wifi_clients[0].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                             passphrase="Automation@123",
                                             country="US")
        time.sleep(10)
        dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"********* Dut IP **********: {dut_ip}")
        rasp_mac_address = wifi_clients[0].interfaces.wifi.get_mac_address()
        logger().info(f"raspi_mac: {rasp_mac_address}")
        client_ip = wifi_clients[0].interfaces.wifi.get_ip_address()
        logger().info(f"Client_ip: {client_ip}")
        time.sleep(30)
        logger().info(f"Initiating wlan ping from RASPI_STA for ping_count")
        rc, stdout, stderr = wifi_clients[0].interfaces.wifi.shell.execute(
            f"sudo ping -c {10} {dut_ip}")
        assert rc == 0, f"RASPI-STA failed to ping DUT"
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"*********{dut_mac_address}**********")

        try:
            wifi_clients[1].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                                 passphrase="Automation@123",
                                                 country="US")
        except:
            logger().info(
                f"RASPI-STA2 unable to connect to AP when client limit is set to 1 which is expected behavior")
        logger().info(f'RASPI-STA1 Disconnecting from DUT-AP')
        wifi_clients[0].interfaces.wifi.leave()

        logger().info("Stop Sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c19432')
def test_wifi_zephyr_dutap_multiclient_connect_disconnect_c19432(wifi_sniffer, wifi_dut, wifi_clients,
                                                                 zephyr_wifi_collections, utf_constants,
                                                                 sniffer_filter, request):
    """AP functionality, If many clients are connected & disconnected multiple times"""
    try:
        capture_filename = request.node.name
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             testcase_no=19432)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        for i in range(4):
            zephyr_wifi_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                          dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                          rasp_mac_address=wifi_clients[
                                                              i].interfaces.wifi.get_mac_address())

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c19430')
def test_wifi_zephyr_max_stas_connect_and_ping_c19430_c19432(wifi_sniffer, wifi_dut,
                                                             wifi_clients, zephyr_wifi_collections, utf_constants,
                                                             sniffer_filter, request):
    """Verify ping functionality with multiple clients"""
    try:
        capture_filename = request.node.name
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             testcase_no=19432)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'],
            filter_name='beacon')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  beacon in Sniffer'
        for asso_id in range(4):
            packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=ap_dut_obj.dut_addr_dict['dut_mac_address'], association_id=asso_id + 1,
                filter_name='apmode_association_id')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
                f"unable to find apmode_association_id_{asso_id + 1}"

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.test_src_map_id('c996280')
def test_wifi_zephyr_dutap_disconnect_multiple_clients_c996280(wifi_sniffer, wifi_dut, wifi_clients,
                                                               zephyr_wifi_collections, utf_constants,
                                                               sniffer_filter, request):
    """Disconnect all connected clients from AP"""
    try:
        capture_filename = request.node.name
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename,
                                             testcase_no=19432, leave=False)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        rasp_mac_address1 = wifi_clients[0].interfaces.wifi.get_mac_address()
        rasp_mac_address2 = wifi_clients[1].interfaces.wifi.get_mac_address()
        rasp_mac_address3 = wifi_clients[2].interfaces.wifi.get_mac_address()
        rasp_mac_address4 = wifi_clients[3].interfaces.wifi.get_mac_address()

        wifi_dut.interfaces.wifi.disconnect_client(sta_mac=rasp_mac_address1)
        wifi_dut.interfaces.wifi.disconnect_client(sta_mac=rasp_mac_address2)
        wifi_dut.interfaces.wifi.disconnect_client(sta_mac=rasp_mac_address3)
        wifi_dut.interfaces.wifi.disconnect_client(sta_mac=rasp_mac_address4)

        wifi_clients[0].interfaces.wifi.leave()
        for i in range(4):
            zephyr_wifi_collections.ap_sniffer_validation(wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                          dut_mac_address=ap_dut_obj.dut_addr_dict['dut_mac_address'],
                                                          rasp_mac_address=wifi_clients[
                                                              i].interfaces.wifi.get_mac_address())

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'DUT_IN_STA_MODE',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    }
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.test_src_map_id('C996276')
def test_wifi_zephyr_dut_ap_mode_soft_reset_ap_to_sta_c19450(wifi_sniffer, wifi_dut, wifi_clients, channel,
                                                             wifi_access_point, utf_constants, zephyr_wifi_collections,
                                                             sniffer_filter, request
                                                             ):
    """Soft Reset functionality when DEVUT moving from AP mode to STA mode"""
    try:
        capture_filename = request.node.name
        ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                             utf_constants, capture_filename=capture_filename + "ap_mode",
                                             testcase_no=19465)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("********* configuring the sniffer with access point channel *********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename + "sta_mode")
        time.sleep(3)
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces.wifi.wifi_cleanup_interface_for_sta_mode()
        logger().info(f"Mode change from AP to STA")
        wifi_dut.interfaces.wifi.mode_change(mode=ZEPHYROperationalModes.WIFI_STA_MODE)
        zephyr_wifi_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                     wifi_access_point=wifi_access_point,
                                                     power_save=False,
                                                     associated=wifi_dut.interfaces.wifi.associated,
                                                     retry_count=3, ping_after_power_save=False,
                                                     ping_count=ping_count)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
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
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.parametrize("channel", [11])
def test_wifi_zephyr_dut_soft_reset_sta_to_ap_viceversa_for_multiple_times_c996276(wifi_sniffer, wifi_dut, wifi_clients,
                                                                                   channel,
                                                                                   wifi_access_point,
                                                                                   utf_constants,
                                                                                   zephyr_wifi_collections,
                                                                                   sniffer_filter, request):
    """Soft Reset functionality when dUT moving from STA mode to AP mode"""
    try:
        iteration_count = utf_constants.get("sta_to_ap_reset_long_run")
        capture_filename = request.node.name
        for count in range(1, iteration_count):
            logger().info(f"Iteration count -------------------->   {count}")
            logger().info("********* configuring the sniffer with access point channel *********")
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename + "sta" + str(count))
            time.sleep(3)
            ping_count = utf_constants.get("ping_count")
            if count > 1:
                wifi_dut.interfaces.wifi.wifi_cleanup_interface_for_sta_mode()
                logger().info(f"Mode change from AP to STA")
                wifi_dut.interfaces.wifi.mode_change(mode=ZEPHYROperationalModes.WIFI_STA_MODE)
            zephyr_wifi_collections.join_to_wifi_network(wifi_dut=wifi_dut,
                                                         wifi_access_point=wifi_access_point,
                                                         power_save=False,
                                                         associated=wifi_dut.interfaces.wifi.associated,
                                                         retry_count=3, ping_after_power_save=False,
                                                         ping_count=ping_count)
            ap_bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {ap_bssid}')
            wifi_dut.interfaces.wifi.leave()
            wifi_sniffer.interfaces.capture.stop_capture()

            wifi_dut.interfaces.wifi.wifi_cleanup_interface_for_ap_mode()
            if count > 1:
                wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename + "ap" + str(count))
                wifi_dut.interfaces.wifi.mode_change()
                # zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                #                                                    static_subnet="255.255.255.0")
                logger().info(" ********** Starting DUT as an AP ********* ")
                wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123",
                                                  channel=11)
                time.sleep(30)
                wifi_sniffer.interfaces.capture.stop_capture()
            else:
                logger().info("come to this part")
                ap_dut_obj = ApModeClientConnections(wifi_dut, wifi_clients, wifi_sniffer, zephyr_wifi_collections,
                                                     utf_constants,
                                                     capture_filename=capture_filename + "ap" + str(count),
                                                     testcase_no=19465, sniffer_stop=True)
                ap_dut_obj.start()
                ap_dut_obj.wait_for_exit()


    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    },
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
def test_wifi_zephyr_sta_inactive_for_5_minutes_c19439(wifi_sniffer, wifi_dut, wifi_clients,
                                                       zephyr_wifi_collections, sniffer_filter, switch, request):
    """APUT's functionality when the station is inactive for 5 minutes"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()

        da_addr = wifi_clients[1].interfaces.wifi.get_mac_address()
        wifi_clients[1].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                             passphrase="Automation@123",
                                             country="US")

        logger().info("***** Turn off client *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        time.sleep(360)

        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr, da_addr=da_addr,
            filter_name="null_based_keepalive")
        logger().info(f"packet_filter1: {packet_filter1}")
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                           packet_filter2="    Type/Subtype:")

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous displayed frame:\s)\d+\.\d+)', lines)
        logger().info(f"Time delta: {time_delta}")

        time_delta = [float(x) for x in time_delta]

        assert 320 > time_delta[-1] >= 300, "Keep-alive time is not in specified time limit"
        logger().info("**** Keep-alive functionality verified successfully ****")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)


'''
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    },
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
def test_wifi_zephyr_ap_keep_alive_10_sec_c996270(wifi_sniffer, wifi_dut, wifi_clients,
                                                 zephyr_wifi_collections, sniffer_filter, switch, request):
    """APUT's functionality when the station is inactive for 5 minutes"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        wifi_dut.interfaces.wifi.wifi_ap_config(config_type=ZephyrApConfigParams.WIFI_AP_CONFIG_PARAM_MAX_INACTIVITY,
                                                max_inactivity=10)
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()

        da_addr = wifi_clients[1].interfaces.wifi.get_mac_address()
        wifi_clients[1].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                             passphrase="Automation@123",
                                             country="US")

        logger().info("***** Turn off client *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        time.sleep(360)

        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr, da_addr=da_addr,
            filter_name="null_based_keepalive")
        logger().info(f"packet_filter1: {packet_filter1}")
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                           packet_filter2="    Type/Subtype:")

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous displayed frame:\s)\d+\.\d+)', lines)
        logger().info(f"Time delta: {time_delta}")

        time_delta = [float(x) for x in time_delta]

        assert 320 > time_delta[-1] >= 300, "Keep-alive time is not in specified time limit"
        logger().info("**** Keep-alive functionality verified successfully ****")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)


@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    },
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
def test_wifi_zephyr_ap_keep_alive_120_sec_c996271(wifi_sniffer, wifi_dut, wifi_clients,
                                                  zephyr_wifi_collections, sniffer_filter, switch, request):
    """APUT's functionality when the station is inactive for 5 minutes"""
    try:
        capture_filename = request.node.name
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=11)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        time.sleep(1)
        wifi_dut.interfaces.wifi.mode_change()
        wifi_dut.interfaces.wifi.wifi_ap_config(config_type=ZephyrApConfigParams.WIFI_AP_CONFIG_PARAM_MAX_INACTIVITY,
                                                max_inactivity=120)
        zephyr_wifi_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76",
                                                           static_subnet="255.255.255.0")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="SILABS_AP_MODE", security="WPA2", psk="Automation@123", channel=11)
        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()

        da_addr = wifi_clients[1].interfaces.wifi.get_mac_address()
        wifi_clients[1].interfaces.wifi.join(ssid="SILABS_AP_MODE", security=SecurityMode.WPA2,
                                             passphrase="Automation@123",
                                             country="US")

        logger().info("***** Turn off client *****")
        switch.interfaces.pdu_switch.turn_off(delay=10)

        time.sleep(360)

        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=sa_addr, da_addr=da_addr,
            filter_name="null_based_keepalive")
        logger().info(f"packet_filter1: {packet_filter1}")
        wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1,
                                                           packet_filter2="    Type/Subtype:")

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        lines = filter_file.read()
        time_delta = re.findall(r'((?<=Time delta from previous displayed frame:\s)\d+\.\d+)', lines)
        logger().info(f"Time delta: {time_delta}")

        time_delta = [float(x) for x in time_delta]

        assert 320 > time_delta[-1] >= 300, "Keep-alive time is not in specified time limit"
        logger().info("**** Keep-alive functionality verified successfully ****")

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(20)
'''
