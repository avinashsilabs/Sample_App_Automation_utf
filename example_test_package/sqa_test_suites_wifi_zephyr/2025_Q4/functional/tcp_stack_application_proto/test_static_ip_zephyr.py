import pytest
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger


"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G : gnbax
        2. Association of Third party AP's
        3. Configure static IPV4 address
        4. Ping to DUT from remote peer

    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. NUC device for Sniffer

    Author: Vinod.G
"""


def logger():
    return get_logger(__name__)


class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_client=None, sniffer_filter=None, wifi_sniffer=None,
                 zephyr_wifi_collections=None, test_name=None, remote_socket_factory=None, ap_mac_address=None,
                 remote_socket=None, allocate_static_ip=0, mqtt_client=None, mqtt_server=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.zephyr_wifi_collections = zephyr_wifi_collections
        self.test_name = test_name
        self.dut_addr = None
        self.device_ip = None
        self.ap_mac_address = ap_mac_address
        self.sniffer_filter = sniffer_filter
        self.wifi_sniffer = wifi_sniffer
        self.enc = "ccmp"
        self.remote_socket_factory = remote_socket_factory
        self.remote_socket = remote_socket
        self.allocate_static_ip = allocate_static_ip
        self.mqtt_client = mqtt_client
        self.mqtt_server = mqtt_server

    def run(self):
        try:
            if self.allocate_static_ip:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  ping_after_power_save=False,
                                                                                  enc=self.enc, ip_config_disable=1)
            else:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  ping_after_power_save=False,
                                                                                  enc=self.enc)
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.start_state("wifi_dut", wifi='init')
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open', "passphrase": '123456789'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_ipv4_allocate_static_ip_address_c49347(
        sniffer_filter, wifi_access_point, wifi_dut, zephyr_wifi_collections, wifi_sniffer, request,
        remote_socket, wifi_client):
    """This test case verifies assignment of static ip address to DUT"""
    try:
        test_name = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections, test_name=test_name,
                                     sniffer_filter=sniffer_filter,
                                     wifi_client=wifi_client, remote_socket=remote_socket, allocate_static_ip=1)
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        ip_parts = host_ip.split('.')
        ip_parts[-1] = str(int(ip_parts[-1]) + 1)
        dut_ip_static = '.'.join(ip_parts)

        ip_parts = dut_ip_static.split('.')
        ip_parts[-1] = "1"
        static_gateway = '.'.join(ip_parts)

        dut_ip = wifi_dut.interfaces.wifi.start_ip(static_ip=dut_ip_static, static_subnet="255.255.255.0",
                                                   static_gateway=static_gateway)
        dut_mac_address = wifi_thread.dut_addr['dut_mac_address']
        logger().info(f" DUT_MAC_ADDRESS : {dut_mac_address}")
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f" AP_MAC_ADDRESS: {ap_mac_address}")
        device_ip = dut_ip.ip.decode()
        logger().info(f" DUT_IP: {device_ip}")

        status = zephyr_wifi_collections.ping(device_ip=device_ip, ping_count=10)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"

        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=dut_mac_address,
                                                                                  da_addr=ap_mac_address,
                                                                                  filter_name='dhcp_discover')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)['packet_count'] == 0, \
            'Able to find the dhcp discover packets in the sniffer capture which is not expected'
        logger().info("No DHCP packets sent from DUT which is expected behavior")

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
