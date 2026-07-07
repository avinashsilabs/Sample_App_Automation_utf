import time
import pytest
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf_wifi_zephyr.interfaces.zephyr_wifi_test_agent_cli import AsyncEventIdentifiers
import re
from utf.utf_config import UtfConfig

"""The testcases added in this file run below test steps for DUT(Soc917)
        1. Configuration of DUT in 2G : gnbax
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Verify DHCP renewal functionality

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
                 remote_socket=None, allocate_static_ip=0, mqtt_client=None, mqtt_server=None, power_save=None):
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
        self.power_save = power_save

    def run(self):
        try:
            if self.allocate_static_ip:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  ping_after_power_save=True,
                                                                                  enc=self.enc, ip_config_disable=1,
                                                                                  power_save=self.power_save)
            else:
                self.dut_addr = self.zephyr_wifi_collections.join_to_wifi_network(wifi_dut=self.wifi_dut, retry_count=3,
                                                                                  wifi_access_point=self.wifi_access_point,
                                                                                  associated=self.wifi_dut.interfaces.wifi.associated,
                                                                                  ping_after_power_save=True,
                                                                                  enc=self.enc,
                                                                                  power_save=self.power_save)
                logger().info(
                    f"device_ip, device_mac : {self.dut_addr['device_ip']}, {self.dut_addr['dut_mac_address']}")

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    def delta_between_dhcp_req_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff


@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": 'OPEN'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C792366')
def test_wifi_zephyr_dhcp_renewal_time_to_2_min_renewal_func_c792366(wifi_sniffer, wifi_access_point, wifi_client,
                                                                     wifi_dut,
                                                                     utf_constants, request, zephyr_wifi_collections,
                                                                     dhcp_lease,
                                                                     sniffer_filter):
    """ The test case verifies DHCP renewal functionality when DHCP renewal time is set to 120 seconds"""
    time_delta = 60
    packet_filter2 = '        DHCP: Request (3)'
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")
    status = None
    wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_lease="120")
    time.sleep(10)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                 wifi_sniffer=wifi_sniffer,
                                 zephyr_wifi_collections=zephyr_wifi_collections,
                                 sniffer_filter=sniffer_filter,
                                 power_save=power_save
                                 )
    wifi_thread.start()
    wifi_thread.wait_for_exit()
    logger().info("Wait for 600 seconds")
    time.sleep(600)
    wifi_sniffer.interfaces.capture.stop_capture()
    mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    try:
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        time.sleep(2)
        device_address = {'sa_addr': mac_address, 'da_addr': da_addr,
                          'wlan_addr': mac_address}
        filters_name = {1: 'dhcp'}
        output_1 = zephyr_wifi_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                                 device_address,
                                                                                 filters_name=filters_name)
        logger().info(f'\n OUTPUT 1 = {output_1}\n')
        assert all(output_1.values()), 'Unable to find expected filter'
        filters_name_1 = {1: 'dhcp_renewal'}
        output_2 = zephyr_wifi_collections.sniffer_validation_for_packet_filters(wifi_sniffer, sniffer_filter,
                                                                                 device_address,
                                                                                 filters_name=filters_name_1,
                                                                                 packet_filter2=packet_filter2)
        logger().info(f'\n OUTPUT 1 = {output_2}\n')
        assert all(output_2.values()), 'Unable to find expected filter'
        dhcp_request_packets_time_delta_list = wifi_thread.delta_between_dhcp_req_packet()
        logger().info(f'Probe packet time delta list= {dhcp_request_packets_time_delta_list}')
        dhcp_request_packets_time_delta_list.pop(0)
        logger().info(f'DHCP Req packet time delta list after removing 0 = {dhcp_request_packets_time_delta_list}')

        for time_diff in dhcp_request_packets_time_delta_list:
            print(int(time_diff))
            is_between = int(time_diff) in range(50, time_delta)
            if is_between is False:
                logger().info(f"{is_between}")
                status = is_between
                break
            else:
                logger().info(f"{is_between}")
                status = is_between
        assert status, 'value is out of range so test case is failed'
        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        packet_filter = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=mac_address,
                                                                                       da_addr=ap_mac_address,
                                                                                       filter_name='power_mgmt_bit')
        if power_save:
            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter)['packet_count'], \
                'Sniffer: Unable to find power management bit 1 in sniffer '
    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_lease="3600")


@pytest.mark.skip()
@pytest.mark.config("wifi_access_point", wifi={"security": 'OPEN'})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
    }
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.test_src_map_id('C792367')
def test_wifi_zephyr_dhcp_ip_change_notification_c792367(wifi_sniffer, wifi_access_point, wifi_client,
                                                         wifi_dut,
                                                         utf_constants, request, zephyr_wifi_collections,
                                                         sniffer_filter):
    """ The test case verifies IP change notification to host"""
    try:
        capture_filename = request.node.name
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2",
                                                         dhcp_end="192.168.50.99",
                                                         dhcp_lease="120")

        time.sleep(10)

        wifi_thread = WifiJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                     wifi_sniffer=wifi_sniffer,
                                     zephyr_wifi_collections=zephyr_wifi_collections,
                                     sniffer_filter=sniffer_filter,
                                     )
        wifi_thread.start()
        wifi_thread.wait_for_exit()
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.100",
                                                         dhcp_end="192.168.50.200",
                                                         dhcp_lease="120")
        logger().info("wait for 180 seconds")
        time.sleep(180)
        events = wifi_dut.interfaces.wifi.get_async_events()
        ip_change_notification = ""
        for event in events:
            if event.event_type == AsyncEventIdentifiers.IP_CHANGE_NOTIFICATION:
                ip_change_notification = event.event_data
        logger().info(f"*********{ip_change_notification}*************")
        assert ip_change_notification, f"unable to find ip_change_notification"
        logger().info("ip_change_notification event is received by DUT when range changed in AP")

        # Extract IP address after "Address[1]:"
        match = re.search(r"Address\[1\]:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ip_change_notification)
        ip_address_dut = match.group(1) if match else None
        if ip_address_dut:
            status = zephyr_wifi_collections.ping(device_ip=ip_address_dut, ping_count=10)
            assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        else:
            assert 0, "IP address received through ip change notification event is not proper"
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as e:
        zephyr_wifi_collections.exception_handling(wifi_dut=wifi_dut, exception=e)
    finally:
        wifi_dut.interfaces.wifi.leave()
        wifi_access_point.interfaces.wifi.enable_dhcp_ap(dhcp_start="192.168.50.2",
                                                         dhcp_end="192.168.50.254",
                                                         dhcp_lease="3600")
