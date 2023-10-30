import time
import uuid
from datetime import datetime
import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xCustomFeatureBitMap, Si91xOperatingMode
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger




def logger():
    return get_logger(__name__)


""" Test Steps:
        1. Configure the DUT in Wlan & coex mode for 2.4Ghz.
        2. Initiate the Scan from DUT.
        3. Initiate the connection with third party Access Point.
        4. Run the traffic TCP/UDP TX & RX.
        5. Verify the throughput of values TCP/UDP TX & RX values.  

    setup requirement:
        1. DUT(SiWG917)
        2. Si-MB4002A
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Author: Shaik Abdul Azeez
"""

class validation_sniffer:
    """ Method to verify dhcp renewal by checking the time difference b/w successive dhcp requests
    is lease_time/2 or 87.5% of lease time and also verifies null frames with powersave"""

    def dhcp_renewal(self, wifi_dut, wifi_access_point, wifi_sniffer, testcase, dhcp_lease, sniffer_filter):

        sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"Device mac address: {sa_addr}")
        da_addr = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP MAC: {da_addr}")
        filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr,da_addr=da_addr,filter_name='power_mgmt_bit')
        filter_2 = f"wlan.addr == {sa_addr} && dhcp"

        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr={sa_addr},filter_name='dhcp_renewal')

        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info("DHCP decryption is in progress : Validating the DORA process")

        logger().info("Sniffer validation for dhcp packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_3)["packet_count"], \
            'Unable to find the power save sniffer packets'

        logger().info("calling the method from tshark filter_time_stamp")
        current_time = time.time()
        updated_capture_file = 'filter_' + testcase + '_' + str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"

        wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{filter_1}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}")
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        result = wifi_sniffer.interfaces.capture.fetch_packet_time_stamp(filter_2,
                                                                         wlan_filter_file)
        assert result, f"Unable to find the time stamp for the {filter_2}"
        logger().info(f"DHCP request packet list {result}")
        result.pop(0)  # Pop the first element because always the reference packet will be set to 0
        count = 0
        if len(result) >= 2:
            diff_time_dhcp_request = [float(result[i + 1]) - float(result[i]) for i in range(0, len(result) - 1)]
            logger().info(f"time difference between successive dhcp requests :{diff_time_dhcp_request}")
            for i in range(0, len(diff_time_dhcp_request)):
                logger().info(f"time diff {float(diff_time_dhcp_request[i])}")
                if float((dhcp_lease / 2) - 10) < (float(diff_time_dhcp_request[i])) <= float((dhcp_lease / 2) + 10):
                    logger().info(
                        f"DHCP request packet found for {float(dhcp_lease / 2)} seconds lease time and the dhcp request "
                        f"packet time is {float(diff_time_dhcp_request[i])}")
                    count = count+1
                elif float((dhcp_lease / 2) - 5) < (float(diff_time_dhcp_request[i])) <= float((dhcp_lease * 87.5) / 100):
                    logger().info(
                        f"DHCP request packet found for 87.5% of lease time time and the dhcp request packet time "
                        f"difference is {float(diff_time_dhcp_request[i])}")
                    count = count+1
                else:
                    rangelist = [x for x in range(int((dhcp_lease / 2) - 10), int((dhcp_lease / 2) + 10))]
                    logger().info(f"expected packet should be in :{rangelist}")
                    for j in rangelist:
                        logger().info(f"**{diff_time_dhcp_request[i]}*{j}**{float(diff_time_dhcp_request[i]) % float(j)}*")
                        if float(diff_time_dhcp_request[i]) % float(j) <= 2:
                            logger().info(f"observed pkt diff is multiple of lease time:{diff_time_dhcp_request[i]}"
                                          f" multiple of {j}")
                            count = count + 1
            assert (float(count/len(diff_time_dhcp_request))*100) >= 80, "expected pkts are not found with the given lease time"
        else:
            assert False, "DHCP list doesnot contain two request time stamps to compare"

    def start(self):
        pass


class WifiJoinThread(ThreadBase):
    """This function is responsible for wifi connectivity ,powersave ,data transfer"""

    def __init__(self, wifi_sniffer=None, wifi_dut=None, \
                 wifi_access_point=None, wifi_client=None, \
                 net_perf_client=None, protocol=None, sl_collections=None, ping_count=None,
                 sniffer_filter=None, data_transfer=None, traffic_type=None, testcase=None, test_case_no=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.data_transfer = data_transfer
        self.traffic_type = traffic_type
        self.test_case_no = test_case_no
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.dut_addr = None


    def run(self):
        logger().info("starting the sniffer again")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        time.sleep(3)

        if self.test_case_no == 19292:
            logger().info(f"=======>>>>>Verifying Static IP<<<<<<<======")
            self.sl_collections.scan(wifi_dut=self.wifi_dut)
            self.sl_collections.connect(wifi_dut=self.wifi_dut, wifi_access_point=self.wifi_access_point)
            self.sl_collections.configure_dut_in_static_ip(self.wifi_dut, static_ip='192.168.50.210', static_subnet='255.255.255.0',
                                                           static_gateway='192.168.50.1')
            self.wifi_dut.interfaces.wifi.set_performance_profile(mode='power_save_low_latency')
        else:
            # logger().info(f"==========>>>>>>>>>>=======>>>>>>>>>")
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     retry_count=3, ping_after_power_save=True,
                                                                     ping_count=self.ping_count, power_save=True)
        time.sleep(2)
        if self.test_case_no == 19293:
            logger().info(f"Verifying dhcp renewal")
            time.sleep(10)
        if self.data_transfer:
            host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"Remote device ip :{host_ip}")
            if self.traffic_type == "TX":
                # starting iperf
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol=self.protocol)
                self.net_perf_client.interfaces.net_perf.start()
                logger().info("sending data from DUT")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.server_port,
                                                    size=1460, ttl=90, throughput_type=1, qos=0)
                # # get and print throughput
                tp = self.net_perf_client.interfaces.net_perf.process_output()
                assert tp is not None, "Throughput not found"
                logger().info("data transfer successful")
                time.sleep(3)
            if self.traffic_type == "RX":

                self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=
                self.dut_addr['device_ip'], protocol=self.protocol, bandwidth="68M")

                self.net_perf_client.interfaces.net_perf.start()

                logger().info("receiving data from Host")
                # open socket and listen for data
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1460, ttl=90, throughput_type=3, qos=0)
                logger().info("data received is successful")
                time.sleep(3)
        if self.test_case_no == 19295:
            time.sleep(15)
        if self.test_case_no == 19296:
            time.sleep(15)
        if self.test_case_no == 19293:
            logger().info(f"Disconnection will issued after verification")
            self.wifi_sniffer.interfaces.capture.stop_capture()
        else:
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_verify_static_ip_allocation_to_dut_c19292(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request, sl_collections, sniffer_filter):

    testcase = request.node.name
    ping_count = utf_constants.get("ping_count")
    sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"Device mac address: {sa_addr}")
    da_addr = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {da_addr}")
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, sl_collections=sl_collections, ping_count=ping_count, test_case_no=19292)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        time.sleep(2)
        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)["packet_count"], \
            'Unable to find the power save sniffer packets'
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.parametrize("dhcp_lease", [120])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "120", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_dhcp_renewal_time_to_2_min_renewal_func_c19293(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut,
                                       utf_constants, request, sl_collections, dhcp_lease, sniffer_filter):
    ping_count = utf_constants.get("ping_count")
    capture_filename = request.node.name
    sa_addr = wifi_dut.interfaces.wifi.get_mac_address()
    da_addr = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP MAC: {da_addr}")
    logger().info(f"DUT MAC is : {sa_addr}")
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=capture_filename, wifi_client=wifi_client, sl_collections=sl_collections,
                              ping_count=ping_count, test_case_no=19293
                              )
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
        logger().info(f"Waiting for half an hour to verify dhcp renewal ")
        time.sleep(10)
        filter_1 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(sa_addr=sa_addr, da_addr=da_addr,
                                                                                  filter_name='power_mgmt_bit')
        filter_2 = f"wlan.addr == {sa_addr} && dhcp"

        filter_3 = sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(wlan_addr={sa_addr},
                                                                                  filter_name='dhcp_renewal')

        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info("DHCP decryption is in progress : Validating the DORA process")

        logger().info("Sniffer validation for dhcp packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=filter_1)["packet_count"], \
            'Unable to find the power save sniffer packets'

        logger().info("calling the method from tshark filter_time_stamp")
        current_time = time.time()
        updated_capture_file = 'filter_' + capture_filename + '_' + str(
            datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
        file_name = f'./reports/{updated_capture_file}.pcap'
        local_capture_file = file_name
        wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"

        wifi_sniffer.interfaces.capture.shell(
            f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{filter_3}' -T fields -e "
            f"frame.number -w "
            f"{wlan_filter_file}")
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
            sftp.get(wlan_filter_file, local_capture_file)
        result = wifi_sniffer.interfaces.capture.fetch_packet_time_stamp(filter_2,
                                                                         wlan_filter_file)
        assert result, f"Unable to find the time stamp for the {filter_2}"
        logger().info(f"DHCP request packet list {result}")
        result.pop(0)  # Pop the first element because always the reference packet will be set to 0
        count = 0
        if len(result) >= 2:
            diff_time_dhcp_request = [float(result[i + 1]) - float(result[i]) for i in range(0, len(result) - 1)]
            logger().info(f"time difference between successive dhcp requests :{diff_time_dhcp_request}")
            for i in range(0, len(diff_time_dhcp_request)):
                logger().info(f"time diff {float(diff_time_dhcp_request[i])}")
                if float((dhcp_lease / 2) - 10) < (float(diff_time_dhcp_request[i])) <= float((dhcp_lease / 2) + 10):
                    logger().info(
                        f"DHCP request packet found for {float(dhcp_lease / 2)} seconds lease time and the dhcp request "
                        f"packet time is {float(diff_time_dhcp_request[i])}")
                    count = count + 1
                elif float((dhcp_lease / 2) - 5) < (float(diff_time_dhcp_request[i])) <= float(
                        (dhcp_lease * 87.5) / 100):
                    logger().info(
                        f"DHCP request packet found for 87.5% of lease time time and the dhcp request packet time "
                        f"difference is {float(diff_time_dhcp_request[i])}")
                    count = count + 1
                else:
                    rangelist = [x for x in range(int((dhcp_lease / 2) - 10), int((dhcp_lease / 2) + 10))]
                    logger().info(f"expected packet should be in :{rangelist}")
                    for j in rangelist:
                        logger().info(
                            f"**{diff_time_dhcp_request[i]}*{j}**{float(diff_time_dhcp_request[i]) % float(j)}*")
                        if float(diff_time_dhcp_request[i]) % float(j) <= 2:
                            logger().info(f"observed pkt diff is multiple of lease time:{diff_time_dhcp_request[i]}"
                                          f" multiple of {j}")
                            count = count + 1
            assert (float(count / len(
                diff_time_dhcp_request)) * 100) >= 80, "expected pkts are not found with the given lease time"
        else:
            assert False, "DHCP list doesnot contain two request time stamps to compare"
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_tcp_tx_functionality_while_dhcp_renewal_c19295(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="TX", test_case_no=19295)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_access_point", wifi={"dhcp_lease": "100", "security": 'OPEN'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    }
)
def test_tcp_rx_functionality_while_dhcp_renewal_c19296(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants, request, sl_collections):
    ping_count = utf_constants.get("ping_count")
    testcase = request.node.name
    wlan_obj = WifiJoinThread(wifi_sniffer=wifi_sniffer, wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                              testcase=testcase, wifi_client=wifi_client, net_perf_client=net_perf_client,
                              protocol=protocol, sl_collections=sl_collections,
                              ping_count=ping_count, data_transfer=True, traffic_type="RX", test_case_no=19296)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()
    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)