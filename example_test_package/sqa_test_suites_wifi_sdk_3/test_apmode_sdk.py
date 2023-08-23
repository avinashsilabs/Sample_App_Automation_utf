import time
import pytest
from utf.interfaces.wifi import WlanError
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xOperatingMode, Si91xFeatureBitMap, Si91xTCPIPFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap, \
    Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI

"""Test Author = Jyothi Nagireddy

        1. Start the sniffer before connection
        2. Required A7 EVK(DUT) board 
        3. Stop the sniffer
        4. Initiate ping from the dut
        5. Analysing all sniffer capture packets and find the arp announcement packet

setup requirement:
        1. DUT
        2. Raspberry PI4 - 2 and more
        3. Access Point(Third Party AP's)
"""


def logger():
    return get_logger(__name__)



class ApMode_ClientConns(ThreadBase):
    def __init__(self, wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections, capture_filename=None, channel=None, dtim_count=None,
                 beacon_interval=None,  static_ip=None, static_subnet=None, static_gateway=None, dut_add=None, leave=True, configure_dut_in_static_mode=True, no_of_clients=None):
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.wifi_clients = wifi_clients
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.capture_filename = capture_filename
        self.channel = channel
        self.dtim_count = dtim_count
        self.beacon_interval = beacon_interval
        self.static_ip = static_ip
        self.static_subnet = static_subnet
        self.static_gateway = static_gateway
        self.dut_add = dut_add
        self.leave = leave
        self.configure_dut_in_static_mode = configure_dut_in_static_mode
        self.no_of_clients = no_of_clients

        if self.configure_dut_in_static_mode:
            logger().info("********** configuring the sniffer with access point channel **********")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
            time.sleep(3)
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, self.static_ip, self.static_subnet,
                                                           self.static_gateway)

    def run(self):
            self.dut_addr = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                       self.channel, self.dtim_count,
                                                                        self.beacon_interval, self.no_of_clients)
            logger().info("Stop sniffer finally")
            self.wifi_sniffer.interfaces.capture.stop_capture()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
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
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19454",
            "passphrase": "12345678",
            "country": "US",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_ap_mode_tx_rules_USregion_C19454(wifi_dut, wifi_client, wifi_clients, wifi_access_point, channel, wifi_sniffer,
                                                   sl_collections, ssid):
    ''' Verify whether DUT is obeying transmission rules(Transmitting with only given power as per channel) according to the inputs given in the set region ap api when region selected is US and region parameters are defined by user'''
    try:
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                        channel=channel, capture_filename="test_C19454", static_ip="192.168.100.76", static_subnet="255.255.255.0", static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=4)
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="beacon_ap_mode_us_region")
        logger().info(f"packet_filter1: {packet_filter1}")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region US in Sniffer'

    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19456", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "JP",
    }
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19456",
            "passphrase": "12345678",
            "country": "JP",
            "channel": "13",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [13])
def test_wifi_sdk_ap_mode_tx_rules_JPregion_C19456(wifi_dut, wifi_client, wifi_access_point, channel, wifi_sniffer,
                                                   wifi_clients, sl_collections,  ssid):
    '''Verify whether DUT is obeying transmission rules(Transmitting with only given power as per channel) according to the inputs given in the set region ap api when region selected is JP and region parameters are defined by the user'''
    try:
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                        channel=channel, capture_filename="test_C19456",
                                        static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                        static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=4)
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="beacon_ap_mode_jp_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region JP in Sniffer'

    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [13])
def test_wifi_sdk_ap_mode_tx_rules_EUregion_C19455(wifi_dut, wifi_client, wifi_access_point, channel, wifi_sniffer,
                                                   wifi_clients, sl_collections, ssid):
    '''Verify whether DUT is obeying transmission rules(Transmitting with only given power as per channel) according to the inputs given in the set region ap api when region selected is EU and region parameters are defined by user'''
    try:
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                       channel=channel, capture_filename="test_C19455",
                                        static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                        static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=4)
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="beacon_ap_mode_eu_region")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find beacon frame with Region EU in Sniffer'
    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19444", "passphrase": "12345678", "beacon": 100,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19444",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("dtim_period", [1, 2, 3, 6, 10])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_various_dtim_intervals_C19444(wifi_sniffer, wifi_dut, wifi_client, wifi_clients, channel,
                                                utf_constants, ssid, dtim_period, wifi_access_point, sl_collections):
    '''Verify DTIM intervals by configuring different DTIM intervals(1,2,3,6,10)'''
    try:
        beacon = 100
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_clients, wifi_sniffer, sl_collections,
                                        channel=channel, dtim_count=dtim_period, capture_filename="test_C19444",
                                        static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                        static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="probe_request")
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="association_request")
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="beacon_ap_mode_dtim_interval")
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="beacon_ap_mode_dtim_period")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  probe request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  association request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter3)['packet_count'], \
            f'Unable to find dtim period: {dtim_period} in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter4=packet_filter4)['packet_count'], \
            f'Unable to find beacon interval: {beacon} in Sniffer'
    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19443", "passphrase": "12345678",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19443",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("beacon", [100, 200, 600, 1000])
@pytest.mark.parametrize("channel", [11])
# beacon interval 600, 1000 not working
def test_wifi_sdk_DUTAP_diff_beacon_intervals_C19443(wifi_sniffer, wifi_access_point, wifi_dut, wifi_client, beacon,
                                                     channel,
                                                     wifi_clients, sl_collections, ssid):
    '''Verify beacon intervals by configuring different beacon intervals(100,200,600,1000)'''
    try:
        if beacon in [600, 1000]:
            pytest.skip(
                f"Beacon interval '{beacon}' not working, Raspi-STA is not finding DUT-AP for beacon interval '{beacon}'")
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                       channel=channel, beacon_interval=beacon, capture_filename="test_C19443",
                                        static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                        static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="probe_request")
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="association_request")
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="beacon_ap_mode_dtim_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  probe request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  assoication request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter3)['packet_count'], \
            f'Unable to find beacon interval: {beacon} in Sniffer'

    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
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
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19432",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_DUPAP_multiclient_connect_disconnect_C19432(wifi_sniffer, wifi_dut, wifi_client, wifi_clients, channel,
                                                             sl_collections, ssid, wifi_access_point):
    '''AP functionality, If many clients are connected & disconnected multiple times'''
    try:
        beacon = 100
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                        channel=channel, capture_filename="test_C19432",
                                        static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                        static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=4)
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address= ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="probe_request")
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="association_request")
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="beacon_ap_mode_dtim_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  probe request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  assoication request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter3)['packet_count'], \
            f'Unable to find dtim period: {beacon} in Sniffer'

    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | Si91xTCPIPFeatureBitMap.Ping,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode,
        #"band": RS9116Band.TwoPointFourGHz,
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
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        1: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        2: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
        3: {
            "security": "WPA2",
            "ssid": "SILABS_AP_C19442",
            "passphrase": "12345678",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.parametrize("channel", [11])
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
def test_wifi_sdk_Max_STAs_connect_and_ping_C19430_C19442(wifi_sniffer, wifi_client, wifi_access_point, wifi_dut, wifi_clients,
                                                          channel,
                                                           ssid, sl_collections):
    '''AP Sequence with many STAS connected'''
    try:
        beacon = 100
        ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                        channel=channel, capture_filename="test_C19454",
                                        static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                        static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=4)
        assert len(wifi_clients) >= 4, f"Minimum 4 raspi devices needed for this test"
        ap_dut_obj.start()
        ap_dut_obj.wait_for_exit()
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="probe_request")
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            radio_ch=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="association_request")
        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            filter_name="beacon_ap_mode_dtim_interval")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find  probe request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
            'Unable to find  assoication request in Sniffer'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter3)['packet_count'], \
            f'Unable to find dtim period: {beacon} in Sniffer'
        packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                            wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                            filter_name="association_response")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter4=packet_filter4)['packet_count'], \
            f'Unable to find association response in Sniffer'
        association_ids = sl_collections.get_association_id()
        if association_ids.association_ids is None:
            logger().info(f'Unable to find ASSOCIATION-ID={association_ids}')
            assert False
        else:
            logger().info(f'\n\n *** ASSOCIATION-ID={association_ids} *** \n')
        raspi_mac_address = []
        for i in range(0, len(wifi_clients)):
            logger().info(f"********** Validating qos data packets from RASPI-STA{i + 1} **********")
            raspi_mac_address.append(wifi_clients[i].interfaces.wifi.get_mac_address())
            logger().info(f"RASPI-STA{i + 1}_MAC_Address: {raspi_mac_address[i]}")
            packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=raspi_mac_address[i],
                                                                                da_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                                filter_name="data_packets")
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter5)['packet_count'], \
                f'Unable to find qos data packets in Sniffer'

        for i in range(0, len(wifi_clients)):
            logger().info(f'Initiating Disconnection on RASPI-STA{i + 1}')
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as e:
        logger().info(f"\n******Testcase failed with  {e}******")
        raise e


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19437", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19437",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [10])
def test_wifi_sdk_apmode_connectivity_with_wrong_psk_Cli_C19437(wifi_sniffer, wifi_dut, wifi_client, channel, sl_collections):
    # thread not used
    sl_collections.configure_dut_in_static_ip(wifi_dut, static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                 static_gateway="192.168.100.76")
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
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        filter_name="deauthentication")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  deauth packet in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        filter_name="disassociation")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
        'Unable to find  disassoc in Sniffer'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2",
        "ssid": "RS9116_AP",
        "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "region_code_ap": "US ", "channel": 14,

    },
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_wifi_sdk_DUTAP_USregion_unsupported_channel_C19458(wifi_dut, wifi_sniffer, channel):
    dut_ip = wifi_dut.interfaces.wifi.ip
    logger().info(f"********* Dut IP **********: {dut_ip}")
    if not dut_ip:
        logger().info("********* configuring static ip to DUT *********")
        wifi_dut.interfaces.wifi.start_ip(static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                                 static_gateway="192.168.100.76")
        with pytest.raises(WlanError) as exc_info:
            logger().info(" ********** Starting DUT as an AP with region as US and channel as 14 ********* ")
            wifi_dut.interfaces.wifi.start_ap(channel=channel)
            logger().info(f"error code received:{exc_info.value.error_code}")
        assert exc_info.value.error_code == 0xA, "Did not receive the desired error code from DUT, failing the test"
        logger().info("Found the desired error code 0xA, marking the test case passed")


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19447", "passphrase": "12345678", "dtim": 4,
        "region_code_ap": "US ",
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19447",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("htcaps-NA")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("beacon", [100, 200, 300])
def test_wifi_sdk_DUTAP_TCP_Tx_Rx_C19447(wifi_sniffer, wifi_access_point, net_perf_client, wifi_dut, wifi_client, wifi_clients,
                                         protocol,
                                         channel, beacon, utf_constants, sl_collections):
    '''Data transfer TX and RX by enabling HT CAPs in AP mode'''
    ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                  channel=channel, beacon_interval=beacon, capture_filename="test_C19447",
                                    static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                    static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    # iperf code
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="HT_IE")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  HT_IE in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        wlan_radio_channel=wifi_access_point.interfaces.wifi.channel,
                                                                        filter_name="beacon_interval")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        'Unable to find  beacon interval in Sniffer'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19436", "passphrase": "12345678", "beacon": 100,
    },
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19436",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("htcaps support-NA")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.parametrize("channel", [10])
def test_wifi_sdk_DUTAP_verify_beacon_format_C19436(wifi_sniffer, wifi_dut, wifi_client, channel,
                                                    utf_constants, sl_collections, ssid, wifi_clients):
    '''Verify beacon format sent by APUT'''
    beacon = 100
    ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                    channel=channel, beacon_interval=beacon, capture_filename="test_C19436",
                                    static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                    static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    # wifi_dut.interfaces.wifi.set_htcaps()
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  beacon frame in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon_ap_mode_dtim_interval")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        f'Unable to find dtim interval in Sniffer'
    packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="HT_IE")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter3=packet_filter3)['packet_count'], \
        'Unable to find  HT_IE in Sniffer'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19446", "passphrase": "12345678", "region_config": 0, "beacon": 100,
        "dtim": 4,
        "region_code_ap": "US ",
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19446",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.skip("htcaps support")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_wifi_sdk_DUT_APMode_11n_htcaps_support_C19446(wifi_sniffer, wifi_dut, wifi_client, channel, protocol,
                                                       sl_collections, wifi_clients):
    '''HT CAP Functionality ,High through put capabilities in AP mode'''
    logger().info(" ********** Starting DUT as an AP ********* ")
    # wifi_dut.interfaces.wifi.set_htcaps()
    ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                    channel=channel, capture_filename="test_C19446",
                                    static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                    static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  beacon frame in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="HT_IE")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        'Unable to find HT_IE in Sniffer'


@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client
                          | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
        "security": "WPA2", "ssid": "SILABS_AP_C19449", "passphrase": "test1234", "channel": 11,
    }
)
@pytest.mark.config(
    "wifi_client",
    wifi={
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19449",
                "passphrase": "12345678",
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
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_DUT_soft_reset_sta_to_ap_C19449(wifi_sniffer, wifi_dut, wifi_clients, wifi_client, channel,
                                                  wifi_access_point,
                                                  utf_constants, sl_collections):
    '''Soft Reset functionality when DEVUT moving from STA mode to AP mode'''
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    logger().info(" ******* start capturing with Sniffer for sta mode ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_DUT_softreset_statoap_C19449')
    time.sleep(3)
    dut_addr = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_addr['dut_mac_address'], ap_bssid)
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_bssid,
                                                                        da_mac_address=dut_addr['dut_mac_address'],
                                                                        filter_name="data_packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        f'Unable to find qos data packets in Sniffer'
    logger().info("Initiating wireless deinit")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    logger().info("Initiating wireless init to change DUT STA mode to AP Mode ")
    wifi_dut.interfaces.wifi.sl_net_init(oper_mode=6, coex_mode=9, retries=3)
    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(oper_mode=6, coex_mode=9)
    ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                    channel=channel, capture_filename="test_C19449",
                                    static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                    static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit()
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  beacon in Sniffer'



@pytest.mark.wifi_client("raspi_wifi")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.Aggregation | Si91xFeatureBitMap.PSKSecurity,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        #"band": RS9116Band.TwoPointFourGHz,
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
           0: {
                "security": "WPA2",
                "ssid": "SILABS_AP_C19450",
                "passphrase": "12345678",
                "channel": 11,
                "interface": "wlan0",
               }
         }
)
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize("channel", [11])
def test_wifi_sdk_DUT_AP_Mode_soft_reset_ap_to_sta_C19450(wifi_sniffer, wifi_dut, wifi_client, wifi_clients,  channel,
                                                          wifi_access_point, utf_constants, ssid, sl_collections):
    '''Soft Reset functionality when DEVUT moving from AP mode to STA mode'''
    logger().info("********* configuring the sniffer with access point channel *********")
    ap_dut_obj = ApMode_ClientConns(wifi_dut, wifi_client, wifi_clients, wifi_sniffer, sl_collections,
                                    channel=channel, capture_filename="test_C19450",
                                    static_ip="192.168.100.76", static_subnet="255.255.255.0",
                                    static_gateway="192.168.100.76", configure_dut_in_static_mode=True, leave=True, no_of_clients=1)
    ap_dut_obj.start()
    ap_dut_obj.wait_for_exit(0)
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="beacon")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find  beacon in Sniffer'
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_dut_obj.dut_addr['rasp_mac_address'],
                                                                        da_mac_address=ap_dut_obj.dut_addr['dut_mac_address'],
                                                                        filter_name="data_packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter2=packet_filter2)['packet_count'], \
        f'Unable to find qos data packets in Sniffer'
    logger().info("Initiating wireless de init")
    wifi_dut.interfaces.wifi.sl_net_deinit()
    logger().info("Initiating wireless init to change DUT AP mode to STA Mode ")
    wifi_dut.interfaces.wifi.sl_net_init(oper_mode=0, coex_mode=9, retries=3)
    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(oper_mode=0, coex_mode=9)
    logger().info("********* configuring the sniffer with access point channel *********")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_C19450_dut_sta')
    time.sleep(3)
    dut_addr = sl_collections.join_to_wifi_network(utf_constants, wifi_dut, wifi_access_point)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    logger().info("Stop sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    sl_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer, dut_addr['dut_mac_address'] , ap_bssid)
    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_bssid,
                                                                        da_mac_address=dut_addr['dut_mac_address'],
                                                                        filter_name="data_packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter4=packet_filter1)['packet_count'], \
        f'Unable to find qos data packets in Sniffer'
