from utf.utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode, Si91xRegionCode, Si91xJoinFeatureBitMap
import re
import subprocess
import time
import pytest
from threading import Thread
from retry import retry
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf_wiseconnect_3.tests.interfaces import Protocol


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

    Author: Vishakha / Saurabh  / Shravanti 

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

    @staticmethod
    def bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid, softap_psk="Automation@123", softap_channel=11, capture_filename=None):
        """Join RefAP (VAP0), start SoftAP (VAP1), connect STA-Client. Shared by C1763302–C1763316."""
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=softap_channel)
        if capture_filename:
            wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")

        result = sl_collections.join_to_wifi_network(
            wifi_dut, wifi_access_point, power_save=False, retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}, DUT STA IP: {dut_sta_ip}, DUT MAC: {dut_mac_address}")

        sl_collections.configure_dut_in_static_ip(
            wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
            static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(
            ssid=softap_ssid, security="WPA2", psk=softap_psk, channel=softap_channel,
            dtim_beacon_count="1", beacon_interval="100")
        ip_dict = ConcurrentMode.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        logger().info(f"SoftAP path DUT-AP={ip_dict['dut_ip']} STA-Client={ip_dict['client1_ip']}")
        return {
            "dut_sta_ip": dut_sta_ip,
            "dut_mac_address": dut_mac_address,
            "dut_ap_ip": ip_dict['dut_ip'],
            "client_ip": ip_dict['client1_ip'],
        }


def wifi_dut_marker(ext_custom_bit=0, wifi_thread_count=1):
    config = {
        "thread_config": {"wifi": {"count": wifi_thread_count, "stack_len": 2048}},
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


def wifi_client_marker(ssid):
    return pytest.mark.config(
        "wifi_client",
        wifi={
            "security": "WPA2",
            "ssid": ssid,
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    )


WIFI_AP_11AX_CH11 = pytest.mark.config(
    'wifi_access_point',
    wifi={'security': 'WPA2', 'standard': 'gnbax', 'channel': 11},
)


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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148302')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148303')
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
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148304')
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
        "security": "WPA2", "ssid": "TEST_C148306", "passphrase": "Automation@123", "beacon": 100, "channel": "13",
        "region": 1,
        "region_code": "europe"
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA2",
        "ssid": "TEST_C148306",
        "passphrase": "Automation@123",
        "country": "GE",
        "channel": "13",
        "interface": "wlan0"

    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={'security': 'WPA2', 'standard': 'gnbax', 'channel': 13, 'region': 'europe'})
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148306')
def test_conn_ping_on_EU_region_C148306(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sl_collections, sniffer_filter):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148306"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=13)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148306", security="WPA2", psk="Automation@123", channel=13,
                                          dtim_beacon_count="1", beacon_interval="100")
        con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        logger().info("\n\nChecking DUT STA connectivity")
        logger().info(f"********* Dut STA IP **********: {dut_sta_ip}")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")

        logger().info("Validating Assoc Req with HE information")
        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=result['dut_mac_address'], filter_name='assoc_req_he_info')

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find Assoc Req  with HE information in sniffer"

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_soft_ap_interface()


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
@pytest.mark.test_src_map_id('C148307')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148308')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148309')
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
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C148310')
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


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763302")
@pytest.mark.net_perf_clients(["raspi_iperf", "raspi_iperf2"])
@pytest.mark.config(
    "net_perf_clients",
    net_perf={
        0: {
            "type": 'iperf',
            "zip_results": 'Y',
            "host": {"TCP": {"port": 5201}, "UDP": {"port": 5202}},
            "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
        1: {
            "type": 'iperf',
            "zip_results": 'Y',
            "host": {"TCP": {"port": 5203}, "UDP": {"port": 5204}},
            "device": {"TCP": {"port": 6201, "data_len": 1380}, "UDP": {"port": 6202, "data_len": 1390}},
        },
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763302')
def test_concurrent_steady_state_throughput_latency_C1763302(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections,
        net_perf_clients):
    """C1763302 / RSCDEV-23009.

    Concurrent 11ax STA (VAP0) + SoftAP (VAP1) steady-state baseline:
    SoftAP path TCP upload from STA-Client for 30s, parallel STA path UDP @ 20 Mbps,
    and ping at 200 ms on both paths. Record throughput/latency; ping loss must be < 1%.
    """
    traffic_duration_sec = 30
    ping_interval_sec = 0.2
    ping_count = int(traffic_duration_sec / ping_interval_sec)
    iperf_error = []
    ping_stats = {}

    def _packet_loss_percent(stdout):
        logger().info("\n\nInitiate packet loss percent\n\n")
        text = stdout.decode() if isinstance(stdout, bytes) else stdout
        match = re.search(r"([\d.]+)%\s*packet\s*loss", text)
        assert match, f"Unable to parse ping packet loss from:\n{text}"
        return float(match.group(1))

    def _run_softap_tcp_tx(device_ip, host_ip):
        try:
            # DUT-AP TCP TX to STA-Client (same as C1763303). DUT TCP RX
            # (throughput_type=3 / remote-terminate) never returns CLI status
            # while STA UDP is running on the other agent thread.
            sl_collections.run_traffic(
                wifi_dut=wifi_dut, net_perf_client=net_perf_clients[1],
                protocol=IperfConstants.TCP, device_ip=device_ip, host_ip=host_ip,
                timeout=traffic_duration_sec, traffic_type="TX")
        except Exception as err:
            iperf_error.append(err)
            raise

    def _run_sta_udp_tx(device_ip, host_ip):
        try:
            sl_collections.run_traffic(
                wifi_dut=wifi_dut, net_perf_client=net_perf_clients[0],
                protocol=IperfConstants.UDP, device_ip=device_ip, host_ip=host_ip,
                timeout=traffic_duration_sec, traffic_type="TX")
        except Exception as err:
            iperf_error.append(err)
            raise

    def _ping_softap_path(dest_ip):
        logger().info(
            f"SoftAP-path ping from STA-Client to DUT-AP {dest_ip} "
            f"(-c {ping_count} -i {ping_interval_sec})")
        rc, stdout, stderr = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c {ping_count} -i {ping_interval_sec} {dest_ip}")
        logger().info(f"\n{stdout.decode() if isinstance(stdout, bytes) else stdout}\n")
        ping_stats["softap_loss"] = _packet_loss_percent(stdout)
        assert rc == 0, f"SoftAP-path ping failed: {stderr}"

    def _ping_sta_path(dest_ip):
        logger().info(
            f"STA-path ping to DUT-STA {dest_ip} (-c {ping_count} -i {ping_interval_sec})")
        result = subprocess.run(
            ["ping", "-c", str(ping_count), "-i", str(ping_interval_sec), dest_ip],
            capture_output=True)
        stdout = result.stdout.decode("utf-8")
        logger().info(f"\n{stdout}\n")
        ping_stats["sta_loss"] = _packet_loss_percent(stdout)
        assert result.returncode == 0, f"STA-path ping failed: {result.stderr.decode('utf-8')}"

    try:
        endpoints = ConcurrentMode.bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid="TEST_C1763302", capture_filename="test_c1763302")
        host_ip = wifi_client.interfaces.wifi.get_ip_address('eth1')
        logger().info(f"HOST IP: {host_ip}")

        # Start SoftAP TCP TX first so DUT iperf is issued before STA UDP uses thread B.
        softap_thread = Thread(
            target=_run_softap_tcp_tx,
            args=(endpoints["dut_ap_ip"], endpoints["client_ip"]), name="softap_tcp_c1763302")
        ping_threads = [
            Thread(target=_ping_softap_path, args=(endpoints["dut_ap_ip"],),
                   name="softap_ping_c1763302"),
            Thread(target=_ping_sta_path, args=(endpoints["dut_sta_ip"],),
                   name="sta_ping_c1763302"),
        ]

        logger().info("Initiating threads for softap & ping traffic simultaneously")
        for t in (softap_thread, *ping_threads):
            t.daemon = True
            t.start()
        time.sleep(5)

        sta_thread = Thread(
            target=_run_sta_udp_tx,
            args=(endpoints["dut_sta_ip"], host_ip), name="sta_udp_c1763302")
        sta_thread.daemon = True
        sta_thread.start()

        join_timeout = traffic_duration_sec + 40
        for t in (softap_thread, sta_thread, *ping_threads):
            t.join(timeout=join_timeout)
            assert not t.is_alive(), f"{t.name} did not finish within expected time"

        assert not iperf_error, f"Concurrent traffic failed: {iperf_error[0]}"
        logger().info(
            f"Ping loss SoftAP={ping_stats.get('softap_loss')}% STA={ping_stats.get('sta_loss')}%")
        assert ping_stats.get("softap_loss", 100) < 1, (
            f"SoftAP-path ping loss {ping_stats.get('softap_loss')}% >= 1%")
        assert ping_stats.get("sta_loss", 100) < 1, (
            f"STA-path ping loss {ping_stats.get('sta_loss')}% >= 1%")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
        try:
            for npc in net_perf_clients:
                npc.interfaces.net_perf.close_files()
                npc.interfaces.net_perf.iperf_process.stop(5)
        except Exception:
            pass


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763303")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763303')
def test_sta_vap_disable_enable_softap_tcp_not_purged_C1763303(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections,
        protocol, net_perf_client):
    """SW_SQA_TC-13270 / C1763303 / RSCDEV-23008.

    Concurrent 11ax STA (VAP0) + SoftAP (VAP1): while TCP runs on SoftAP path between
    STA-Client and DUT-AP, administratively disable then re-enable STA VAP. SoftAP TCP
    must continue (AP TX queues must not be purged).
    """
    iperf_error = []
    traffic_duration_sec = 60
    sta_disable_after_sec = 10
    sta_reenable_wait_sec = 5

    def _sta_disconnect_keep_ap_sockets():
        """Disable DUT STA (VAP0) without leave()/close_sockets so SoftAP TCP stays up.

        leave() also close_sockets() and would drop SoftAP TCP. Disconnect is issued on
        the second WIFI agent thread while SoftAP iperf holds thread 0. The CLI often
        ACKs Success without an immediate prompt, so wait longer than leave()'s 5s.
        """
        wifi = wifi_dut.interfaces.wifi
        line = "wifi.client.disconnect -i client"
        logger().info(f"***** STA VAP disable (no socket close): {line} *****")
        try:
            status, _data = wifi.issue_command_in_thread(
                line, timeout=30, async_timeout=30, protocol=Protocol.WIFI,
                async_identifiers=[])
            wifi.associated = False
            if status != SLStatus.SL_STATUS_OK:
                logger().info(
                    f"STA disconnect status {status}; continue SoftAP TCP check")
        except Exception as err:
            wifi.associated = False
            logger().info(f"STA disconnect CLI: {err}; continue SoftAP TCP check")

    def _run_softap_tcp_tx(device_ip, host_ip):
        try:
            sl_collections.run_traffic(
                wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                device_ip=device_ip, host_ip=host_ip, timeout=traffic_duration_sec,
                traffic_type="TX")
        except Exception as err:
            iperf_error.append(err)
            raise

    try:
        endpoints = ConcurrentMode.bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid="TEST_C1763303", capture_filename="test_c1763303")
        dut_ap_ip, client_ip = endpoints["dut_ap_ip"], endpoints["client_ip"]

        iperf_thread = Thread(
            target=_run_softap_tcp_tx, args=(dut_ap_ip, client_ip), name="softap_tcp_c1763303")
        iperf_thread.daemon = True
        iperf_thread.start()

        time.sleep(sta_disable_after_sec)
        _sta_disconnect_keep_ap_sockets()
        time.sleep(sta_reenable_wait_sec)

        logger().info("***** STA VAP enable + reconnect to RefAP *****")
        sl_collections.join_to_wifi_network(
            wifi_dut, wifi_access_point, power_save=False, retry_count=3, associated=False)

        iperf_thread.join(timeout=traffic_duration_sec + 40)
        assert not iperf_thread.is_alive(), (
            "SoftAP TCP iperf did not finish within expected time after STA disable/enable")
        assert not iperf_error, (
            f"SoftAP TCP failed during STA VAP disable/enable (AP TX queue may have been purged): "
            f"{iperf_error[0]}")

        logger().info("***** Verify STA-Client still reaches DUT-AP after STA VAP cycle *****")
        assert ConcurrentMode.ping_from_wifi_client(wifi_client, dut_ap_ip), (
            "STA-Client lost SoftAP path after STA VAP disable/enable")

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763304")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763304')
def test_softap_disable_enable_sta_tcp_not_purged_C1763304(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections,
        protocol, net_perf_client):
    """SW_SQA_TC-13271 / C1763304 / RSCDEV-23008.

    Concurrent 11ax STA (VAP0) + SoftAP (VAP1): while TCP runs from DUT-STA to
    RefAP/LAN iperf server, administratively stop then restart SoftAP. STA TCP
    must continue (STA TX queues must not be purged).
    """
    iperf_error = []
    traffic_duration_sec = 60
    softap_disable_after_sec = 10
    softap_reenable_after_sec = 10
    softap_ssid = "TEST_C1763304"
    softap_psk = "Automation@123"
    softap_channel = 11

    def _run_sta_tcp_tx(device_ip, host_ip):
        try:
            sl_collections.run_traffic(
                wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                device_ip=device_ip, host_ip=host_ip, timeout=traffic_duration_sec,
                traffic_type="TX")
        except Exception as err:
            iperf_error.append(err)
            raise

    try:
        endpoints = ConcurrentMode.bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid=softap_ssid, softap_psk=softap_psk, softap_channel=softap_channel,
            capture_filename="test_c1763304")
        dut_sta_ip = endpoints["dut_sta_ip"]
        host_ip = wifi_client.interfaces.wifi.get_ip_address('eth1')
        logger().info(f"STA TCP path DUT-STA={dut_sta_ip} HOST={host_ip}")

        iperf_thread = Thread(
            target=_run_sta_tcp_tx, args=(dut_sta_ip, host_ip), name="sta_tcp_c1763304")
        iperf_thread.daemon = True
        iperf_thread.start()

        time.sleep(softap_disable_after_sec)
        logger().info("***** SoftAP VAP disable (stop AP interface) *****")
        try:
            wifi_dut.interfaces.wifi.stop_soft_ap_interface()
        except Exception as err:
            logger().info(f"SoftAP stop CLI: {err}; continue STA TCP check")

        time.sleep(softap_reenable_after_sec)
        logger().info("***** SoftAP VAP enable (same config) + STA-Client rejoin *****")
        # start_ap() defaults to CLI timeout=12. While STA TCP holds thread 0,
        # wifi.ap.start on thread 1 often ACKs late; a timeout here used to
        # exception_handling()/reset the DUT and kill the STA TCP under test.
        try:
            wifi_dut.interfaces.wifi.start_ap(
                ssid=softap_ssid, security="WPA2", psk=softap_psk, channel=softap_channel,
                dtim_beacon_count="1", beacon_interval="100", timeout=30)
        except Exception as err:
            logger().info(f"SoftAP start CLI: {err}; continue STA TCP check")
        try:
            ConcurrentMode.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        except Exception as err:
            logger().info(f"STA-Client rejoin: {err}; continue STA TCP check")

        iperf_thread.join(timeout=traffic_duration_sec + 40)
        assert not iperf_thread.is_alive(), (
            "STA TCP iperf did not finish within expected time after SoftAP disable/enable")
        assert not iperf_error, (
            f"STA TCP failed during SoftAP disable/enable (STA TX queue may have been purged): "
            f"{iperf_error[0]}")

        logger().info("***** Verify DUT STA still reaches RefAP/LAN after SoftAP cycle *****")
        sl_collections.ping(dut_sta_ip, 30, 5)

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763305")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763305')
def test_sta_vap_toggle_softap_udp_no_burst_drops_C1763305(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections,
        protocol, net_perf_client):
    """SW_SQA_TC-13272 / C1763305: SoftAP UDP 60s; STA down t=15, rejoin t=30; no 1s 100% loss; transition <2%."""
    iperf_error = []
    udp_int = re.compile(
        r"\[\s*\d+\]\s+([\d.]+)\s*-\s*([\d.]+)\s+sec\s+([\d.]+)\s+\S+"
        r"\s+[\d.]+\s+\S+(?:\s+[\d.]+\s+\S+\s+(\d+)\s*/\s*(\d+)\s*\(([\d.]+)%\))?")

    def _softap_udp(device_ip, host_ip):
        logger().info("\n\nInitiating SoftAP UDP traffic thread\n\n")
        try:
            sl_collections.run_traffic(
                wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
                device_ip=device_ip, host_ip=host_ip, timeout=60, traffic_type="TX", bandwidth="30M")
        except Exception as err:
            iperf_error.append(err)

    try:
        ep = ConcurrentMode.bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid="TEST_C1763305", capture_filename="test_c1763305")
        iperf_thread = Thread(target=_softap_udp, args=(ep["dut_ap_ip"], ep["client_ip"]))
        iperf_thread.daemon = True
        iperf_thread.start()

        time.sleep(15)
        wifi = wifi_dut.interfaces.wifi
        try:
            wifi.issue_command_in_thread(
                "wifi.client.disconnect -i client", timeout=30, async_timeout=30,
                protocol=Protocol.WIFI, async_identifiers=[])
        except Exception as err:
            logger().info(f"STA disconnect CLI: {err}; continue SoftAP UDP check")
        wifi.associated = False
        time.sleep(15)
        try:
            sl_collections.join_to_wifi_network(
                wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                associated=False, skip_scan=True, ip_config_disable=True)
        except Exception as err:
            logger().info(f"STA rejoin CLI: {err}; continue SoftAP UDP check")

        iperf_thread.join(timeout=100)
        if iperf_error:
            logger().info(f"DUT SoftAP UDP CLI: {iperf_error[0]}; judge from host iperf log")
        assert not iperf_thread.is_alive(), "SoftAP UDP did not finish after STA toggle"

        text = open(net_perf_client.interfaces.net_perf.log_file_path, encoding="utf-8", errors="ignore").read()
        rows = udp_int.findall(text)
        assert rows, "Unable to parse SoftAP UDP interval stats"
        lost = total = 0
        burst = False
        for start, end, _xfer, d_lost, d_tot, loss in rows:
            if float(end) - float(start) > 1.5:
                continue
            if loss and float(loss) == 100:
                burst = True
            if float(end) > 15 and float(start) < 30:
                lost += int(d_lost or 0)
                total += int(d_tot or 0)
        trans = (lost / total * 100) if total else 0
        logger().info(f"SoftAP UDP transition loss={trans:.2f}% burst_100={burst}")
        assert not burst and trans < 2, f"SoftAP UDP burst={burst} transition loss={trans:.2f}%"
        assert ConcurrentMode.ping_from_wifi_client(wifi_client, ep["dut_ap_ip"])
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763307")
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763307')
def test_periodic_softap_start_stop_sta_icmp_no_gaps_C1763307(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections):
    """SW_SQA_TC-13274 / C1763307: STA ICMP 600x100ms; SoftAP stop/start every 10s; 5s window loss <2%."""
    def _toggle():
        wifi = wifi_dut.interfaces.wifi
        for _ in range(5):
            time.sleep(10)
            try:
                wifi.stop_soft_ap_interface()
            except Exception as err:
                logger().info(f"SoftAP stop CLI: {err}")
            time.sleep(3)
            try:
                wifi.start_ap(ssid="TEST_C1763307", security="WPA2", psk="Automation@123",
                              channel=11, dtim_beacon_count="1", beacon_interval="100", timeout=30)
            except Exception as err:
                logger().info(f"SoftAP start CLI: {err}")

    try:
        ep = ConcurrentMode.bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid="TEST_C1763307", capture_filename="test_c1763307")
        toggle = Thread(target=_toggle)
        toggle.daemon = True
        toggle.start()
        stdout = subprocess.run(
            ["ping", "-c", "600", "-i", "0.1", ep["dut_sta_ip"]], capture_output=True
        ).stdout.decode()
        logger().info(f"\n{stdout}\n")
        toggle.join(timeout=20)
        seqs = {int(s) for s in re.findall(r"icmp_seq=(\d+)", stdout)}
        assert seqs, "No STA ICMP replies parsed"
        for start in range(1, 601, 50):
            loss = (50 - sum(seq in seqs for seq in range(start, start + 50))) * 2
            logger().info(f"STA ICMP seq {start}-{start + 49} loss={loss:.2f}%")
            assert loss < 2, f"STA ICMP 5s window loss {loss:.2f}% (seq {start}-{start + 49})"
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763313")
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763313')
def test_sta_link_flap_softap_icmp_not_dropped_C1763313(
        wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections):
    """SW_SQA_TC-13278 / C1763313: STA-Client ICMP via DUT-AP 600x100ms; STA flap x5; 5s window loss <2%."""
    def _flap_sta():
        wifi = wifi_dut.interfaces.wifi
        for _ in range(5):
            try:
                wifi.issue_command_in_thread(
                    "wifi.client.disconnect -i client", timeout=30, async_timeout=30,
                    protocol=Protocol.WIFI, async_identifiers=[])
            except Exception as err:
                logger().info(f"STA disconnect CLI: {err}")
            wifi.associated = False
            time.sleep(5)
            try:
                sl_collections.join_to_wifi_network(
                    wifi_dut, wifi_access_point, power_save=False, retry_count=3,
                    associated=False, skip_scan=True, ip_config_disable=True)
            except Exception as err:
                logger().info(f"STA rejoin CLI: {err}")

    try:
        ep = ConcurrentMode.bringup_concurrent_sta_softap(
            wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
            softap_ssid="TEST_C1763313", capture_filename="test_c1763313")
        flap = Thread(target=_flap_sta)
        flap.daemon = True
        flap.start()
        _rc, stdout, _err = wifi_client.interfaces.wifi.shell.execute(
            f"sudo ping -c 600 -i 0.1 {ep['dut_ap_ip']}")
        text = stdout.decode() if isinstance(stdout, bytes) else stdout
        logger().info(f"\n{text}\n")
        flap.join(timeout=40)
        seqs = {int(s) for s in re.findall(r"icmp_seq=(\d+)", text)}
        assert seqs, "No SoftAP-path ICMP replies parsed"
        for start in range(1, 601, 50):
            loss = (50 - sum(seq in seqs for seq in range(start, start + 50))) * 2
            logger().info(f"SoftAP ICMP seq {start}-{start + 49} loss={loss:.2f}%")
            assert loss < 2, f"SoftAP ICMP 5s window loss {loss:.2f}% (seq {start}-{start + 49})"
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


# @wifi_dut_marker(wifi_thread_count=2)
# @WIFI_AP_11AX_CH11
# @wifi_client_marker("TEST_C1763316")
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP])
# @pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
# @pytest.mark.test_src_map_id('C1763316')
# def test_sta_scan_during_softap_tcp_C1763316(
#         wifi_dut, wifi_access_point, wifi_sniffer, wifi_client, sniffer_filter, sl_collections,
#         protocol, net_perf_client):
#     """C1763316 / RSCDEV-23008: SoftAP TCP 60s max rate; DUT STA scan every 10s x5."""
#     iperf_error, scan_ok = [], 0
#
#     def _softap_tcp(device_ip, host_ip):
#         try:
#             sl_collections.run_traffic(
#                 wifi_dut=wifi_dut, net_perf_client=net_perf_client, protocol=protocol,
#                 device_ip=device_ip, host_ip=host_ip, timeout=60, traffic_type="TX")
#         except Exception as err:
#             iperf_error.append(err)
#
#     def _sta_scan():
#         nonlocal scan_ok
#         for i in range(5):
#             time.sleep(10)
#             # Foreground wifi.scan is rejected while STA is associated
#             # (0x10002 SCAN_ISSUED_IN_ASSOCIATED_STATE). Title is background scan.
#             try:
#                 wifi_dut.interfaces.wifi.scan(ssid=None, bgscan=True)
#                 scan_ok += 1
#                 logger().info(f"STA scan {i + 1}/5 ok")
#             except Exception as err:
#                 logger().info(f"STA scan {i + 1}/5 CLI: {err}")
#
#     try:
#         ep = ConcurrentMode.bringup_concurrent_sta_softap(
#             wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, sl_collections,
#             softap_ssid="TEST_C1763316", capture_filename="test_c1763316")
#         # Required before associated bg_scan (see test_wifi_bg_scan_after_connect).
#         # Default trigger -40 never fires at RefAP RSSI ~-18.
#         wifi_dut.interfaces.wifi.set_advanced_scan_configuration(
#             adv_trigger_level=0, adv_enable_instant_scan=1)
#         tcp = Thread(target=_softap_tcp, args=(ep["dut_ap_ip"], ep["client_ip"]))
#         scan = Thread(target=_sta_scan)
#         tcp.daemon = scan.daemon = True
#         tcp.start()
#         scan.start()
#         tcp.join(timeout=100)
#         scan.join(timeout=100)
#         if iperf_error:
#             logger().info(f"SoftAP TCP CLI: {iperf_error[0]}; judge from host iperf")
#         assert not tcp.is_alive(), "SoftAP TCP did not finish during STA scans"
#         assert scan_ok == 5, f"STA completed {scan_ok}/5 scans during SoftAP TCP"
#         wifi_sniffer.interfaces.capture.stop_capture()
#     except Exception as error:
#         sl_collections.exception_handling(wifi_dut, error)
#     finally:
#         wifi_dut.interfaces.wifi.stop_ap()


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763319")
@pytest.mark.config(
    "net_perf_client",
    net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763319')
def test_clients_join_leave_softap_not_disturb_sta_udp_C1763319(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        wifi_client,
        sniffer_filter,
        sl_collections,
        protocol,
        net_perf_client):
    """
    SW_SQA_TC-13283 / C1763319

    DUT-STA runs UDP iPerf for 60s while a SoftAP client
    disconnects/reconnects 5 times.
    """

    iperf_error = []

    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c1763319"

        logger().info(
            "********** configuring the sniffer with access point channel **********"
        )

        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}"
        )

        result = sl_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point,
            power_save=False,
            retry_count=3,
            associated=False
        )

        sl_collections.configure_dut_in_static_ip(
            wifi_dut,
            static_ip="192.168.100.76",
            static_subnet="255.255.255.0",
            static_gateway="192.168.100.76"
        )

        logger().info("********** Starting DUT as an AP **********")

        wifi_dut.interfaces.wifi.start_ap(
            ssid="TEST_C1763319",
            security="WPA2",
            psk="Automation@123",
            channel=11,
            dtim_beacon_count="1",
            beacon_interval="100"
        )

        ip_dict = con_obj.connect_clients_to_dut_as_ap(
            [wifi_client],
            wifi_dut
        )

        dut_ip = ip_dict["dut_ip"]
        client_ip = ip_dict["client1_ip"]

        logger().info(
            f"SoftAP path DUT-AP={dut_ip} STA-Client={client_ip}"
        )

        def _churn_client():
            for idx in range(5):

                logger().info(
                    f"SoftAP client churn {idx + 1}/5 : disconnect"
                )

                try:
                    wifi_client.interfaces.wifi.disconnect()
                except Exception as err:
                    logger().info(
                        f"Client disconnect CLI: {err}"
                    )

                time.sleep(2)

                logger().info(
                    f"SoftAP client churn {idx + 1}/5 : reconnect"
                )

                try:
                    con_obj.connect_clients_to_dut_as_ap(
                        [wifi_client],
                        wifi_dut
                    )
                except Exception as err:
                    logger().info(
                        f"Client reconnect CLI: {err}"
                    )

                time.sleep(8)

        churn_thread = Thread(target=_churn_client)

        traffic_thread = Thread(
            target=sl_collections.run_traffic,
            args=(
                wifi_dut,
                net_perf_client,
                protocol,
                60,
                iperf_error
            )
        )

        traffic_thread.start()
        churn_thread.start()

        churn_thread.join()
        traffic_thread.join()

        assert not iperf_error, (
            f"STA UDP traffic failed during SoftAP client churn: "
            f"{iperf_error}"
        )

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)


@wifi_dut_marker(wifi_thread_count=2)
@WIFI_AP_11AX_CH11
@wifi_client_marker("TEST_C1763321")
@pytest.mark.config(
    "net_perf_client",
    net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.test_src_map_id('C1763321')
def test_bidirectional_tcp_queue_sharing_C1763321(
        wifi_dut,
        wifi_access_point,
        wifi_sniffer,
        wifi_client,
        sniffer_filter,
        sl_collections,
        protocol,
        net_perf_client):
    """
    SW_SQA_TC-13285 / C1763321

    Validate queue sharing/separation under bidirectional TCP load.

    DUT-STA runs TCP upload for 300 seconds.
    STA-Client connected through DUT SoftAP runs TCP upload for
    300 seconds simultaneously.
    """

    sta_traffic_error = []
    softap_traffic_error = []

    try:

        con_obj = ConcurrentMode()
        capture_filename = "test_c1763321"

        logger().info(
            "********** configuring the sniffer with access point channel **********"
        )

        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file=f"{capture_filename}"
        )

        sl_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point,
            power_save=False,
            retry_count=3,
            associated=False
        )

        sl_collections.configure_dut_in_static_ip(
            wifi_dut,
            static_ip="192.168.100.76",
            static_subnet="255.255.255.0",
            static_gateway="192.168.100.76"
        )

        logger().info("********** Starting DUT as AP **********")

        wifi_dut.interfaces.wifi.start_ap(
            ssid="TEST_C1763321",
            security="WPA2",
            psk="Automation@123",
            channel=11,
            dtim_beacon_count="1",
            beacon_interval="100"
        )

        ip_dict = con_obj.connect_clients_to_dut_as_ap(
            [wifi_client],
            wifi_dut
        )

        dut_ip = ip_dict["dut_ip"]
        client_ip = ip_dict["client1_ip"]

        logger().info(
            f"SoftAP path DUT-AP={dut_ip} STA-Client={client_ip}"
        )

        sta_thread = Thread(
            target=sl_collections.run_traffic,
            args=(
                wifi_dut,
                net_perf_client,
                protocol,
                300,
                sta_traffic_error
            )
        )

        softap_thread = Thread(
            target=sl_collections.run_traffic,
            args=(
                wifi_client,
                net_perf_client,
                protocol,
                300,
                softap_traffic_error
            )
        )

        logger().info(
            "Starting STA TCP upload and SoftAP TCP upload simultaneously"
        )

        sta_thread.start()
        softap_thread.start()

        sta_thread.join()
        softap_thread.join()

        assert not sta_traffic_error, (
            f"DUT STA TCP traffic failed: {sta_traffic_error}"
        )

        assert not softap_traffic_error, (
            f"SoftAP client TCP traffic failed: {softap_traffic_error}"
        )

        logger().info(
            "Bidirectional TCP load completed successfully"
        )

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)