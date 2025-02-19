from utf.utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode, Si91xRegionCode, Si91xJoinFeatureBitMap
import time
import pytest
from retry import retry
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase


"""This function runs below test steps for DUT-Si91x
        1. Configuration of DUT in 2G : BGN
        2. Configuring Concurrent Mode        
        3. Start the sniffer before connection
        4. Association of Third party AP's
        5. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Stop the sniffer
        8. Analyzing all sniffer capture packets 

    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Vishakha

"""


def logger():
    return get_logger(__name__)



class APModeConnection(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_sniffer=None, remote_wiseconnect3=None, sniffer_filter=None,
                 test_name=None, test_case_no=None, sl_collections=None, ping_count=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.remote_wiseconnect3 = remote_wiseconnect3
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.test_case_no = test_case_no
        self.test_name = test_name
        self.ping_count = ping_count
        self.sl_collections = sl_collections
        self.ssid = "TEST_C148309"
        self.password = "Automation@123"
        self.channel = 11
        self.static_ip = "192.168.100.77"
        self.static_subnet = "255.255.255.0"
        self.static_gateway = "192.168.100.76"
        self.ip_version = 'ipv4'


    def run(self):
        self.sl_collections.configure_dut_in_static_ip(
            self.wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76")
        time.sleep(2)
        self.wifi_dut.interfaces.wifi.start_ap(ssid=self.ssid, security="wpa3", channel=11, psk=self.password,
                                          dtim_beacon_count=1, beacon_interval=100, encryption=None, ht_caps=1)
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.sapi.scan(channel=0, ssid=self.ssid)

        self.remote_wiseconnect3.interfaces.sapi.join(
            ssid=self.ssid, security="wpa3", passphrase=self.password, channel=self.channel, timeout=60)
        time.sleep(5)
        self.remote_wiseconnect3.interfaces.sapi.start_ip(
            ip_version=self.ip_version, static_ip=self.static_ip, static_subnet=self.static_subnet,
            static_gateway=self.static_gateway, timeout=10)

        self.remote_wiseconnect3.interfaces.sapi.ping(
            server_ip=self.static_gateway, num_ping_attempts=self.ping_count, ping_timeout=10, ip_version='ipv4',
            ping_size=64)
        time.sleep(2)
        self.remote_wiseconnect3.interfaces.sapi.leave()

class ConcurrentMode:
    def __init__(self):
        self.dut_ap_ip = None

    @staticmethod
    def connect_clients_to_dut_as_ap(wifi_clients, wifi_dut, count=3, ping_count=10, dut_ip=None):
        ip_dict = {}
        connected = False
        for i in range(len(wifi_clients)):
            logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is joining to DUT-AP")
            wifi_clients[i].interfaces.wifi.join()
            time.sleep(5)
            if dut_ip is None:
                ip_dict['dut_ip'] = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            else:
                ip_dict['dut_ip'] = dut_ip
            logger().info(f"********* Dut as AP IP **********: {ip_dict['dut_ip']}")
            for retry_count in range(count):
                try:
                    logger().info(f"RASPI-STA{i + 1}:'{wifi_clients[i].name}' is successfully connected to DUT-AP")
                    logger().info(f"Initiating wlan ping from client '{wifi_clients[i].name}' to DUT")
                    ip_dict[f'client{i + 1}_ip'] = wifi_clients[i].interfaces.wifi.get_ip_address()
                    logger().info(f"Client{i + 1}_ip: {ip_dict[f'client{i + 1}_ip']}")
                    rc, stdout, stderr = wifi_clients[i].interfaces.wifi.shell.execute(
                        f"sudo ping -c {ping_count} {ip_dict['dut_ip']}")
                    assert rc == 0, f"RASPI-STA{i + 1} failed to ping DUT"
                    logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                    connected = True
                    break
                except Exception as error:
                    logger().info(f"RASPI-STA{i + 1} failed to ping DUT:\n{error}...retry count -> {count + 1}")
                    time.sleep(10)
            assert connected, f"RASPI-STA{i + 1} is disconnected from DUT-AP"
        return ip_dict

    @staticmethod
    def print_throughput(iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    @staticmethod
    @retry(Exception, delay=15, tries=3)
    def ping_from_wifi_client(wifi_client, dest_ip, ping_count=10):
        logger().info(f"Initiating wlan ping from client '{wifi_client.name}' to destination_ip:'{dest_ip}'")
        for count in range(3):
            try:
                rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(f"sudo ping -c {ping_count} {dest_ip}")
                assert rc == 0
                logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
                return rc == 0
            except:
                time.sleep(10)


def wifi_dut_marker(ext_custom_bit=0):
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | ext_custom_bit,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
    }
    return pytest.mark.config("wifi_dut", wifi=config)


@wifi_dut_marker()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2', 'standard': 'gnbax', 'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148302",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_conn_ping_on_different_security_modes_C148302(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                       sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148302"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(security="WPA2", ssid="TEST_C148302", channel=11, dtim_beacon_count="1",
                                          beacon_interval="100", psk="Automation@123")
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req  with HE information in sniffer'

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2', 'standard': 'gnbax', 'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148303",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_terminate_ap_while_running_sta_C148303(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148303"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148303", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)

        validation = True
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req with HE information in sniffer'

        logger().info(" Terminate the AP")
        wifi_dut.interfaces.wifi.sl_net_down(mode="ap")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("beacons checking from DUT AP")
        beacon_filter = f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 8'
        assert not wifi_sniffer.interfaces.capture.sniffer_validation(validation, beacon_filter)['packet_count'],\
            'Found beacons from DUT-AP'

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2', 'standard': 'gnbax', 'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148304",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_terminate_sta_while_running_ap_C148304(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148304"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148304", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req  with HE information in sniffer'

        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


''' EU region not working on channel 12,13'''
@pytest.mark.skip()
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "region": 1,
        "region_code": "Europe"
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2', 'standard': 'gnbax', 'channel': 13, 'region': 'Europe'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148306",
        "passphrase": "Automation@123",
        "channel": 13,
        "interface": "wlan0",
        'region': 'Europe'
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_conn_ping_on_EU_region_C148306(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                        sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148306"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=13)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.Europe)
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.Europe)
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148306_AP", security="WPA2", psk="Automation@123", channel=13,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")
        validation = True
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req  with HE information in sniffer'

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


''' set different region on STA and AP but its not joining'''
@pytest.mark.skip()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        # 'security': 'WPA2', 'standard': 'gnbax', 'channel': 14, 'region': 'Japan'
        'security': 'WPA2', 'standard': 'gnbax', 'channel': 11, 'region': 'Europe'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148307",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
        "region": "US"
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_conn_ping_on_STA_in_JP_and_AP_in_US_region_C148307(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                            sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148307"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_dut.interfaces.wifi.set_wifi_region(region_code=Si91xRegionCode.Europe)
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148307", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req  with HE information in sniffer'

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'open', 'standard': 'gnbax', 'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148308",
        "passphrase": "Automation@123",
        "channel": 11,
        "interface": "wlan0",
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_conn_ping_on_sta_in_open_and_ap_in_wpa2_security_modes_C148308(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                        wifi_client, sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148308"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148308", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req  with HE information in sniffer'

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


'''UTF JIRA: UTF-4705, using secondary DUT to set WPA3 security'''
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
                          | Si91xTCPIPFeatureBitMap.DHCPv4Server,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.Default,
    }
)
@pytest.mark.remote_wiseconnect3("remote_wiseconnect3")
@pytest.mark.config(
    "remote_wiseconnect3",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode |
                               Si91xExtCustomFeatureBitMap.IEEE802_11W,
    },
)
@pytest.mark.config('wifi_access_point',
                    wifi={'security': 'WPA3', 'standard': 'gnbax', "passphrase": 'thisisatestnetwork',
                          "ssid": 'sharma1234', 'channel': 11, 'region': 'Europe'})
@pytest.mark.end_state("wifi_dut", wifi=["unassociated"])
def test_conn_ping_on_wpa3_security_mode_C148309(
        wifi_dut, wifi_access_point, wifi_sniffer, sniffer_filter, sl_collections, remote_wiseconnect3):
    try:
        ping_count = 30
        capture_filename = "test_c148309"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}")

        ap_conn = APModeConnection(wifi_dut=wifi_dut, wifi_sniffer=wifi_sniffer, remote_wiseconnect3=remote_wiseconnect3,
                                   sniffer_filter=sniffer_filter, sl_collections=sl_collections, ping_count=ping_count)

        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable)

        logger().info("**************** join to wifi network **************")
        sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                                            associated=wifi_dut.interfaces.wifi.associated)

        remote_wiseconnect3.interfaces.sapi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)

        ap_conn.start()
        ap_conn.wait_for_exit()

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


@wifi_dut_marker()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA2', 'standard': 'gnbax', 'channel': 11,
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "TEST_C148310",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "TEST_C148310",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_conn_ping_on_multi_client_C148310(wifi_dut, wifi_access_point, wifi_sniffer, wifi_clients,
                                           sniffer_filter, sl_collections):
    try:
        wifi_clients = wifi_clients[:2]
        con_obj = ConcurrentMode()
        capture_filename = "test_c148310"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148310", security="WPA2", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap(wifi_clients, wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']
        client2_ip = ip_dict['client2_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_clients[0], dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"
        logger().info(f"********* Raspi STA2 IP **********: {client2_ip}")
        status = con_obj.ping_from_wifi_client(wifi_clients[1], dut_ip)
        assert status, f"RASPI-STA2 failed to ping to DUT as AP"
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        validation = True
        packet_filter = f'((wlan.addr == {dut_mac_address}) and (wlan.ext_tag.number == 35)) and ' \
                        f'(wlan.fc.type_subtype == 0x0000)'
        logger().info("Validating Assoc Req with HE information")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter)['packet_count'], \
            'Unable to find Assoc Req  with HE information in sniffer'

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
