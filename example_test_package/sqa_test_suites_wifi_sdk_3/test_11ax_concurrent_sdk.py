from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xOperatingMode, Si91xRegionCode, Si91xJoinFeatureBitMap
import time
import pytest
from retry import retry
from utf.utils.logger import get_logger


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


pytestmark = [
    pytest.mark.config(
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
        }
    )
]


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
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info(" Terminate the AP")
        wifi_dut.interfaces.wifi.sl_net_down(mode="ap")
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)

    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
        dut_ap_ip = ip_dict['dut_ip']

        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)

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
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
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
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()

'''need to re-validate, facing issue from station side set WPA3 security'''
@pytest.mark.skip()
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'security': 'WPA3', 'standard': 'gnbax', 'channel': 11, 'region': 'Europe'
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
        "security": "WPA3",
        "ssid": "TEST_C148309",
        "passphrase": "Automation@123",
        "interface": "wlan0",
        "channel": 11,
        "key_mgmt": "SAE",
        "proto": 2
    }
)
@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_conn_ping_on_wpa3_security_mode_C148309(wifi_dut, wifi_access_point, wifi_sniffer, wifi_client,
                                                 sniffer_filter, sl_collections):
    try:
        con_obj = ConcurrentMode()
        capture_filename = "test_c148309"
        logger().info("********** configuring the sniffer with access point channel **********")
        wifi_sniffer.interfaces.capture.configure_interface(channel=11)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        wifi_dut.interfaces.wifi.set_join_feature_bitmap(
            join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable
                                | Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
        logger().info("**************** join to wifi network **************")
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=False,
                                                     retry_count=3, associated=False)
        dut_sta_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP BSSID : {ap_bssid}")
        sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                  static_gateway="192.168.100.76")
        logger().info(" ********** Starting DUT as an AP ********* ")
        wifi_dut.interfaces.wifi.start_ap(ssid="TEST_C148309", security="WPA3", psk="Automation@123", channel=11,
                                          dtim_beacon_count="1", beacon_interval="100")
        ip_dict = con_obj.connect_clients_to_dut_as_ap([wifi_client], wifi_dut)
        dut_ip = ip_dict['dut_ip']
        client1_ip = ip_dict['client1_ip']

        logger().info("\n\nChecking connection stability by pinging from RASPI to DUT as AP")
        logger().info(f"********* Dut IP **********: {dut_ip}")
        sl_collections.ping(dut_ip, 30, 5)
        logger().info(f"********* Raspi STA1 IP **********: {client1_ip}")
        status = con_obj.ping_from_wifi_client(wifi_client, dut_ip)
        assert status, f"RASPI-STA1 failed to ping to DUT as AP"

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()


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

        logger().info("Stop sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_mac_address, ap_bssid,
                                               sniffer_filter, power_save=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut, error)
    finally:
        wifi_dut.interfaces.wifi.stop_ap()
