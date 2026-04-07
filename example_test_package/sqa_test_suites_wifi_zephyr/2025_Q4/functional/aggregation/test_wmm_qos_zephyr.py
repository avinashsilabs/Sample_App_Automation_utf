from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils import print_dict
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, ping_qos
from utf.utils.thread_base import ThreadBase
from threading import Thread
from utf.utf_config import UtfConfig

"""This function runs below test steps :
        1. Configuration of DUT in 2G
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Stop the sniffer  
        8. Analyzing all sniffer capture packets and find the different Qos access category packets


    traffic category for Iperf category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 4  Video
        4. wlan.qos.priority == 6  Voice

    traffic category for Ping category
        1. wlan.qos.priority == 0  Best Effort
        2. wlan.qos.priority == 1  Background
        3. wlan.qos.priority == 4  Video
        4. wlan.qos.priority == 6  Voice

    setup requirement:
        1. soc 
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)
    Author: Vinod.G
"""


def logger():
    return get_logger(__name__)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class WifiJoin(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, net_perf_client=None, wifi_client=None,
                 protocol=None, capture_filename=None, zephyr_wifi_collections=None, power_save=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.capture_filename = capture_filename
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.dut_addr = None
        self.power_save = power_save

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}.pcap")

            self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                              associated=self.wifi_dut.interfaces.wifi.associated, retry_count=3, power_save=self.power_save,
                                                                              ping_after_power_save=True)
        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name",
                         [('0x00', 0, "qos_best_effort_tx"), ('0x20', 1, "qos_back_ground_tx"),
                          ('0x80', 4, "qos_video_tx"), ('0xc8', 6, "qos_voice_tx")])
def test_wifi_zephyr_tcp_data_tx_with_BE_BK_VI_VO_c19752(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                         wifi_client,
                                                         protocol, request, zephyr_wifi_collections, sniffer_filter,
                                                         traffic, qos,
                                                         filter_name):
    """Verifying TCP data Tx with VO, VI, BE, BK traffic type and check sniffer whether the Qos field set as per the
       configured TOS value."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol, tos_value=traffic)
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}, "
                      f"tos_value: {traffic}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=1, qos=qos)
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughput..."
        __print_throughput(tp)
        logger().info("data transfer is successful")
        time.sleep(5)
        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name=filter_name)

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "qos categories packets are not captured in the sniffer"
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wifi_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name",
                         [('0x00', 0, "qos_best_effort_tx"), ('0x20', 1, "qos_back_ground_tx"),
                          ('0x80', 4, "qos_video_tx"), ('0xc8', 6, "qos_voice_tx")])
def test_wifi_zephyr_udp_data_tx_with_BE_BK_VI_VO_c19753(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                         wifi_client,
                                                         protocol, request, zephyr_wifi_collections, sniffer_filter,
                                                         traffic, qos,
                                                         filter_name):
    """Verifying UDP data Tx with VO, VI, BE, BK traffic type and analyzing all sniffer capture packets."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol, tos_value=traffic)
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}, "
                      f"tos_value: {traffic}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** send traffic  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.server_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.server_port,
                                       size=1460, ttl=30, throughput_type=2, qos=qos)
        logger().info(f"***** get and print throughput ******")
        tp = net_perf_client.interfaces.net_perf.process_output()
        assert tp, "failed to get throughput..."
        __print_throughput(tp)
        logger().info("data transfer is successful")
        time.sleep(5)
        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter2 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name=filter_name)

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "qos categories packets are not captured in the sniffer"
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wifi_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_zephyr_ping_from_ap_to_module_ip_with_four_traffics_c19754(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                         request,
                                                                         wifi_client, zephyr_wifi_collections,
                                                                         sniffer_filter):
    """Verifying Ping from AP to module IP with all the four traffics"""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    traffic_category_list = ['0x00', '0x20', '0x80', '0xC8']
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            wifi_client=wifi_client, capture_filename=capture_filename,
                            zephyr_wifi_collections=zephyr_wifi_collections, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        for qos_category in traffic_category_list:
            status = ping_qos(wifi_obj.dut_addr['device_ip'], 30, qos_category=qos_category)
            assert status == 1, "Ping failed"
            time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="qos_best_effort_tx")

        packet_filter4 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="qos_back_ground_tx")

        packet_filter5 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="qos_video_tx")

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name="qos_voice_tx")

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "qos_best_effort packets are not captured in the sniffer"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)[
            'packet_count']
        assert snif_pkt_count, "qos_back_ground packets are not captured in the sniffer"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5)[
            'packet_count']
        assert snif_pkt_count, "qos_video packets are not captured in the sniffer"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)[
            'packet_count']
        assert snif_pkt_count, "qos_voice packets are not captured in the sniffer"
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wifi_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.parametrize("traffic, qos, filter_name",
                         [('0x00', 0, "qos_best_effort_rx"), ('0x20', 1, "qos_back_ground_rx"),
                          ('0x80', 4, "qos_video_rx"), ('0xc8', 6, "qos_voice_rx")])
def test_wifi_zephyr_udp_data_rx_with_BE_BK_VI_VO_c22116(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                         wifi_client,
                                                         protocol, request, zephyr_wifi_collections, sniffer_filter,
                                                         traffic, qos,
                                                         filter_name):
    """Verifying UDP data Rx with VO, VI, BE, BK traffic type and check sniffer whether the Qos field set as per the
       configured TOS value."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        logger().info(f"********** Calling IPERF RX UDP traffic DUT configured as Server **************")
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol, tos_value=traffic, bandwidth="1M")
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}, "
                      f"tos_value: {traffic}")
        logger().info(f"***** starting iperf ******")
        net_perf_client.interfaces.net_perf.start()
        logger().info(f"***** Start listening  ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=2, protocol=17,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=4, qos=qos)
        logger().info("data transfer is successful")
        time.sleep(5)
        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter6 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name=filter_name)

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter6)[
            'packet_count']
        assert snif_pkt_count, "qos_categories packets are not captured in the sniffer"
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wifi_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos, filter_name",
                         [('0x00', 0, "qos_best_effort_rx"), ('0x20', 1, "qos_back_ground_rx"),
                          ('0x80', 4, "qos_video_rx"), ('0xc8', 6, "qos_voice_rx")])
def test_wifi_zephyr_tcp_data_rx_with_BE_BK_VI_VO_c22115(wifi_sniffer, net_perf_client, wifi_access_point, wifi_dut,
                                                         wifi_client,
                                                         protocol, request, zephyr_wifi_collections, sniffer_filter,
                                                         traffic, qos,
                                                         filter_name):
    """Verifying TCP data Rx with VO, VI, BE, BK traffic type and analyzing all sniffer capture packets."""

    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    try:
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"***** Start get IP address ******")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        wifi_obj = WifiJoin(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                            net_perf_client=net_perf_client, wifi_client=wifi_client, protocol=protocol,
                            capture_filename=capture_filename, zephyr_wifi_collections=zephyr_wifi_collections, power_save=power_save)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=wifi_obj.dut_addr['device_ip'],
                                                        protocol=protocol, tos_value=traffic)
        logger().info(f"Host IP: {host_ip}, Dut IP: {wifi_obj.dut_addr['device_ip']}, Protocol: {protocol}, "
                      f"tos_value: {traffic}")

        def start_client():
            time.sleep(3)
            logger().info(f"***** Connect to server  ******")
            net_perf_client.interfaces.net_perf.start()

        client_thread1 = Thread(target=start_client, args=(), )
        client_thread1.start()

        logger().info(f"***** Start listening ******")
        wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                       local_port=net_perf_client.interfaces.net_perf.client_port,
                                       local_ip=wifi_obj.dut_addr['device_ip'], remote_ip=host_ip,
                                       remote_port=net_perf_client.interfaces.net_perf.client_port,
                                       size=1470, ttl=30, throughput_type=3, qos=qos)
        logger().info("data transfer is successful")
        client_thread1.join()
        time.sleep(5)
        logger().info("Dut going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        packet_filter7 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=wifi_obj.dut_addr['dut_mac_address'], filter_name=filter_name)

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter7)[
            'packet_count']
        assert snif_pkt_count, "qos_categories packets are not captured in the sniffer"
        zephyr_wifi_collections.join_sniffer_validation(wifi_access_point, wifi_sniffer,
                                                        wifi_obj.dut_addr['dut_mac_address'], ap_mac_address,
                                                        sniffer_filter, power_save=power_save)

    except Exception as Ex:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


