import ipaddress
import random
import time

import pytest
from debugpy.launcher import channel

from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.wifi.fixtures import wifi_dut, wifi_sniffer
from utf.utf_config import UtfConfig
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xConfigFeatureBitMap, Si91xOperatingMode
)


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Give the SSID, PSK and Security type for Both APUT and STAUT
        2. Give the Server IP as AP Backend machine Link local address
        3. Start the data transfer on 10 ports from 5000 to 5009 on AP Backend machine
        4. Scan and connect the STAUT to 3rd party AP
        5. Start the APUT and connect the 3rd party STA to APUT
        6. Do the data transfer from STAUT to AP Backend machine on 10 Ports

"""


def random_ipv6_addr(network):
    """
    Generate a random IPv6 address in the given network
    Example: random_ipv6_addr("fd66:6cbb:8c10::/48")
    Returns an IPv6Address object.
    """
    net = ipaddress.IPv6Network(network)
    # Which of the network.num_addresses we want to select?
    addr_no = random.randint(0, net.num_addresses)
    # Create the random address by converting to a 128-bit integer, adding addr_no and converting back
    network_int = int.from_bytes(net.network_address.packed, byteorder="big")
    addr_int = network_int + addr_no
    addr = ipaddress.IPv6Address(addr_int.to_bytes(16, byteorder="big"))
    return addr


class MelcoConcurrentMode(ThreadBase):
    """
    Steps:
        1. Set the SSID, PSK and Security type for both APUT and STAUT
        2. Set the Server IP as AP Backend machine Link local address
        3. Start the data transfer on 10 ports from 5000 to 5009 on AP Backend machine
        4. Scan and connect the STAUT to 3rd party AP
        5. Start the APUT and connect the 3rd party STA to APUT
        6. Do the data transfer from STAUT to AP Backend machine on 10 Ports
    """

    def __init__(self, wifi_dut=None, sl_collections=None, test_case=None, sniffer_filter=None, wifi_clients=None,
                 utf_constants=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, protocol=None, testcase_no=None, capture_filename=None,
                 ping=True, traffic_type=None, stop_sniffer=True, leave=False, test_name=None,
                 wifi_client=None, test_id=None, test_type=None, ping_from="remote", ping_count=10, addr_type="link",
                 timeout=60):
        super().__init__()
        self.test_case = test_case
        self.dut_addr_dict = None
        self.ap_mac_address = None
        self.wifi_dut = wifi_dut
        self.sl_collections = sl_collections
        self.wifi_sniffer = wifi_sniffer
        self.sniffer_filter = sniffer_filter
        self.wifi_clients = wifi_clients
        self.utf_constants = utf_constants
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase_no = testcase_no
        self.capture_filename = capture_filename
        self.ping = ping
        self.traffic_type = traffic_type
        self.stop_sniffer = stop_sniffer
        self.leave = leave
        self.no_of_clients = 1
        self.channel = "11"
        self.ssid = "SILABS_AP_MODE"
        self.security = "WPA2"
        self.password = "Automation@123"
        self.utf_constants = utf_constants
        self.channel = channel
        self.capture_filename = None
        self.wifi_sniffer = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.wifi_client = wifi_client
        self.test_id = test_id
        self.ping_from = ping_from
        self.ping_count = ping_count
        self.test_type = test_type
        self.dut_add_dict = None
        self.addr_type = addr_type
        self.traffic_type = traffic_type
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.timeout = timeout
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.remote_ip = None

    def run_traffic(self, protocol, traffic_type, ports=None, ip_version="ipv4", device_ip=None):
        if ports is None:
            ports = range(5001, 5011)  # Default ports from 5001 to 5010

        for port in ports:
            self.sl_collections.run_traffic(
                wifi_dut=self.wifi_dut,
                net_perf_client=self.net_perf_client,
                protocol=protocol,
                device_ip=device_ip,
                host_ip=self.remote_ip,
                timeout=self.timeout,
                traffic_type=traffic_type,
                ip_version=ip_version,
                buffer_size_tcp=1380,
                buffer_size_udp=1390,
                async_socket=1,
                remote_port=port  # Assuming the method supports a port parameter
            )


    def run(self):
        """Start the sniffer by giving the test case name as filename and by configuring the sniffer with access point channel"""
        logger().info("********** configuring the sniffer with access point channel **********")
        self.wifi_sniffer.interfaces.capture.configure_interface(
            channel=self.wifi_access_point.interfaces.wifi.channel)
        logger().info(" ******* start capturing with Sniffer by giving the test case name as filename ******* ")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")
        time.sleep(3)

        """Get the ping count from the utf_constants"""
        ping_count = self.utf_constants.get("ping_count")

        ports = range(5001, 5011)  # Ports from 5001 to 5010

        logger().info(f"**********Test Name: {self.test_name}**********")

        """Join to third party AP"""
        self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point, self.wifi_clients)
        """Fetch remote ip"""
        self.remote_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        """start the traffic with interface"""
        interface = self.wifi_client.interfaces.wifi.config["interface"]
        device_ip = f"{self.dut_add_dict['device_ip']}%{interface}"

        self.wifi_client.interfaces.wifi.config['interface'] = "wlan0"

        """AP mode clients connection"""
        self.dut_addr_dict = self.sl_collections.ap_mode_clients_connection(self.wifi_dut, self.wifi_clients,
                                                                            channel=self.channel, ssid=self.ssid,
                                                                            security=self.security,
                                                                            password=self.password,
                                                                            ping_count=ping_count,
                                                                            no_of_clients=self.no_of_clients,
                                                                            leave=self.leave)

        """Throughput test"""
        if self.test_name == "C641368":
            self.run_traffic(protocol="TCP", traffic_type="TX", ports=ports, device_ip=self.dut_add_dict['device_ip'])

        elif self.addr_type == "link" and self.test_name == "C641369":
            self.run_traffic(protocol="TCP", traffic_type="RX", ports=ports, device_ip=device_ip)

        elif self.test_name == "C641370":
            self.run_traffic(protocol="UDP", traffic_type="TX", ports=ports, device_ip=self.dut_add_dict['device_ip'])

        elif self.addr_type == "link" and self.test_name == "C641371":
            self.run_traffic(protocol="UDP", traffic_type="RX", ports=ports, device_ip=device_ip)

        """stop the sniffer"""
        self.wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("********** stop the sniffer **********")


# pytest markers
@pytest.mark.skip("Test case is not ready")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.test_src_map_id('C641368')
def test_wifi_sdk_check_the_staut_tcp_tx_on_10_sockets_on_dut_concurrent_mode_C641368(wifi_dut, wifi_access_point,
                                                                                      sl_collections, wifi_sniffer,
                                                                                      sniffer_filter, wifi_clients,
                                                                                      utf_constants, protocol):
    """
    Test Steps:
        1. Give the SSID, PSK and Security type for both APUT and STAUT
        2. Give the Server IP as AP Backend machine Link local address
        3. Start the TCP Tx on 10 ports from 5000 to 5009 on AP Backend machine
        4. Scan and connect the STAUT to 3rd party AP
        5. Start the APUT and connect the 3rd party STA to APUT
        6. Do the TCP Tx from STAUT to AP Backend machine on 10 Ports
    """
    try:
        logger().info("Test case C641368")
        melco_concurrent_mode = MelcoConcurrentMode(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                    wifi_clients=wifi_clients, utf_constants=utf_constants,
                                                    wifi_access_point=wifi_access_point, test_name="C641368")
        melco_concurrent_mode.start()
        melco_concurrent_mode.wait_for_exit()
    except Exception as e:
        logger().error(f"Test case C641368 failed with exception: {e}")
        assert False, f"Test case C641368 failed with exception: {e}"


@pytest.mark.skip("Test case is not ready")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.test_src_map_id('C641369')
def test_wifi_sdk_check_the_staut_tcp_rx_on_10_sockets_on_dut_concurrent_mode_C641369(wifi_dut, wifi_access_point,
                                                                                      sl_collections, wifi_sniffer,
                                                                                      sniffer_filter, wifi_clients,
                                                                                      utf_constants, protocol):
    """
    Test Steps:
        1. Give the SSID, PSK and Security type for both APUT and STAUT
        2. Give the Server IP as AP Backend machine Link local address
        3. Start the TCP Rx on 10 ports from 5000 to 5009 on AP Backend machine
        4. Scan and connect the STAUT to 3rd party AP
        5. Start the APUT and connect the 3rd party STA to APUT
        6. Do the TCP Rx from STAUT to AP Backend machine on 10 Ports
    """
    try:
        logger().info("Test case C641368")
        melco_concurrent_mode = MelcoConcurrentMode(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                    wifi_clients=wifi_clients, utf_constants=utf_constants,
                                                    wifi_access_point=wifi_access_point, test_name="C641368")
        melco_concurrent_mode.start()
        melco_concurrent_mode.wait_for_exit()
    except Exception as e:
        logger().error(f"Test case C641368 failed with exception: {e}")
        assert False, f"Test case C641368 failed with exception: {e}"

@pytest.mark.skip("Test case is not ready")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.test_src_map_id('C641370')
def test_wifi_sdk_check_the_staut_udp_tx_on_10_sockets_on_dut_concurrent_mode_C641370(wifi_dut, wifi_access_point,
                                                                                      sl_collections, wifi_sniffer,
                                                                                      sniffer_filter, wifi_clients,
                                                                                      utf_constants, protocol):
    """
    Test Steps:
        1. Give the SSID, PSK and Security type for both APUT and STAUT
        2. Give the Server IP as AP Backend machine Link local address
        3. Start the UDP Tx on 10 ports from 5000 to 5009 on AP Backend machine
        4. Scan and connect the STAUT to 3rd party AP
        5. Start the APUT and connect the 3rd party STA to APUT
        6. Do the UDP Tx from STAUT to AP Backend machine on 10 Ports
    """
    try:
        logger().info("Test case C641368")
        melco_concurrent_mode = MelcoConcurrentMode(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                    wifi_clients=wifi_clients, utf_constants=utf_constants,
                                                    wifi_access_point=wifi_access_point, test_name="C641368")
        melco_concurrent_mode.start()
        melco_concurrent_mode.wait_for_exit()
    except Exception as e:
        logger().error(f"Test case C641368 failed with exception: {e}")
        assert False, f"Test case C641368 failed with exception: {e}"

@pytest.mark.skip("Test case is not ready")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.ConcurrentMode,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.WPSSupportDisabled,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.DHCPv4Server | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0,
        "security": "WPA2", "ssid": "SILABS_AP_MODE", "passphrase": "Automation@123", "channel": 8
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "231469460", "ipv6_state": "1",
                               "wan_ipv6_address": random_ipv6_addr("2401:4900:1cb3::/48")}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_client",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": "11",
            "interface": "wlan0",
        },
    }
)
@pytest.mark.config(
    'wifi_access_point',
    wifi={
        'ssid': 'Concurent_ap',
        'security': 'WPA2',
        'passphrase': 'test1234',
        'channel': 11,
    }
)
@pytest.mark.test_src_map_id('C641371')
def test_wifi_sdk_check_the_staut_udp_rx_on_10_sockets_on_dut_concurrent_mode_C641371(wifi_dut, wifi_access_point,
                                                                                      sl_collections, wifi_sniffer,
                                                                                      sniffer_filter, wifi_clients,
                                                                                      utf_constants, protocol):
    """
    Test Steps:
        1. Give the SSID, PSK and Security type for both APUT and STAUT
        2. Give the Server IP as AP Backend machine Link local address
        3. Start the UDP Rx on 10 ports from 5000 to 5009 on AP Backend machine
        4. Scan and connect the STAUT to 3rd party AP
        5. Start the APUT and connect the 3rd party STA to APUT
        6. Do the UDP Rx from STAUT to AP Backend machine on 10 Ports
    """
    try:
        logger().info("Test case C641368")
        melco_concurrent_mode = MelcoConcurrentMode(wifi_dut=wifi_dut, sl_collections=sl_collections,
                                                    wifi_sniffer=wifi_sniffer, sniffer_filter=sniffer_filter,
                                                    wifi_clients=wifi_clients, utf_constants=utf_constants,
                                                    wifi_access_point=wifi_access_point, test_name="C641368")
        melco_concurrent_mode.start()
        melco_concurrent_mode.wait_for_exit()
    except Exception as e:
        logger().error(f"Test case C641368 failed with exception: {e}")
        assert False, f"Test case C641368 failed with exception: {e}"
