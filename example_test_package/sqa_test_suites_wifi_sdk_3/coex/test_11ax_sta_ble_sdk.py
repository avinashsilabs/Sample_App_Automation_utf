from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xBTFeatureBitMap, \
    Si91xBLEFeatureBitMap, Si91xBLECustomFeatureBitMap, Si91xJoinFeatureBitMap
import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.bluetooth import BLEDeviceState

"""This function runs below test steps for DUT-Si91x
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        6. Enable the power save mode in DUT
        7. Initiates ble in DUT
        8. run ble in slave / master mode
        9. Analyzing all sniffer capture packets
        
    setup requirement:
        1. soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Author: Saurabh Sharma

"""


def logger():
    return get_logger(__name__)


class WifiThreadFunctionality(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, net_perf_client=None, traffic=None, qos=None, protocol=None):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_addr = None
        self.ap_mac_address = None
        self.host_ip = None
        self.iperf_throughput = None
        self.test_case = test_case
        self.net_perf_client = net_perf_client
        self.traffic = traffic
        self.qos = qos
        self.protocol = protocol

    def run(self):
        try:
            self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
            logger().info(f"******** HOST IP {self.host_ip} *******")
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"******** AP MAC ADDRESS {self.ap_mac_address} *******")
            self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                join_feature_bitmap=Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)

            # if self.test_case == "198667":
            #     self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip,
            #                                                          device_ip=self.dut_addr['device_ip'],
            #                                                          protocol=self.protocol, tos_value=self.traffic)
            #     logger().info(
            #         f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
            #         f"tos_value: {self.traffic}")
            #     logger().info(f"***** starting iperf ******")
            #     self.net_perf_client.interfaces.net_perf.start()
            #     logger().info(f"***** send traffic  ******")
            #     self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
            #                                         local_port=self.net_perf_client.interfaces.net_perf.server_port,
            #                                         local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
            #                                         remote_port=self.net_perf_client.interfaces.net_perf.server_port,
            #                                         size=1460, ttl=30, throughput_type=1, qos=self.qos)
            #     logger().info(f"***** get and print throughput ******")
            #     self.iperf_throughput = self.net_perf_client.interfaces.net_perf.process_output()
            #     assert self.iperf_throughput, "failed to get throughput..."
            #     self.__print_throughput()
            #     logger().info("data transfer is successful")
            #     time.sleep(5)

            if self.test_case == "198668":
                self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip,
                                                                     device_ip=self.dut_addr['device_ip'],
                                                                     protocol=self.protocol, tos_value=self.traffic)
                logger().info(
                    f"Host IP: {self.host_ip}, Dut IP: {self.dut_addr['device_ip']}, Protocol: {self.protocol}, "
                    f"tos_value: {self.traffic}")
                logger().info(f"***** start iperf  ******")
                self.net_perf_client.interfaces.net_perf.start()
                logger().info(f"***** Start listening ******")
                self.wifi_dut.interfaces.wifi.iperf(family=2, transfer_type=1, protocol=6,
                                                    local_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    local_ip=self.dut_addr['device_ip'], remote_ip=self.host_ip,
                                                    remote_port=self.net_perf_client.interfaces.net_perf.client_port,
                                                    size=1470, ttl=30, throughput_type=3, qos=self.qos)
                logger().info("data transfer is successful")

        except Exception as e:
            logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")

    def sniffer_validation(self):
        packet_filter1 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address, filter_name="association_request")

        packet_filter2 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.ap_mac_address, da_addr=self.dut_addr['dut_mac_address'], filter_name="association_response")

        packet_filter3 = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
            sa_addr=self.dut_addr['dut_mac_address'], filter_name="probe_request")

        logger().info(f"***** Validating association_request packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association_request packets"

        logger().info(f"***** Validating association_response packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)[
            'packet_count']
        assert snif_pkt_count, "Unable to find association_response packets"

        logger().info(f"***** Validating probe_request packets ******")
        snif_pkt_count = self.wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)[
            'packet_count']
        assert snif_pkt_count, "Unable to find probe_request packets"

    def __print_throughput(self):
        if self.iperf_throughput is not None:
            print_dict("##     ", self.iperf_throughput)


class BleThreadFunctionality(ThreadBase):
    def __init__(self, wifi_dut=None, ble_client=None, ble_test_type=None, sl_collections=None, test_case=None,
                 ble_dut=None, ble_pairing=0, ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = None
        self.ble_client_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.ble_dut = ble_dut
        self.ble_pairing = ble_pairing

    def run(self):
        """ *************************** Set up DUT for BLE advertising ***************************** """
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        assert (self.ble_dut_address is not None), "Unable to fetch bluetooth address from DUT"
        logger().info(f" BLE DUT ADDRESS : {self.ble_dut_address}")
        time.sleep(5)

        if self.test_case == "198664":
            self.sl_collections.ble_connection(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                               ble_dut_address=self.ble_dut_address, mode="slave", timeout=20)
            self.ble_client.interfaces.bluetooth.hci_tool_manager.update_conn(dev_addr=self.ble_dut_address,
                                                                              min_conn_interval=36, max_conn_interval=36,
                                                                              conn_latency=0, supervision_timeout=3200)
            logger().info(f'wait for 60 seconds to check ble connection stability')
            time.sleep(60)
            self.wifi_dut.interfaces.wifi.ble_get_device_state()

        # if self.test_case == "198667":
        #     data = "testwentybytesofdata"
        #     service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        #     char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        #     self.ble_dut.interfaces.bluetooth.ble_add_service(uid=0x6E)
        #     self.ble_dut.interfaces.bluetooth.ble_add_char_serv_att(uid=0x6F)
        #     self.ble_dut.interfaces.bluetooth.ble_add_char_val_att(uid=0x6F)
        #     self.sl_collections.ble_connection(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
        #                                        ble_dut_address=self.ble_dut_address, mode="master", timeout=20)
        #
        #     servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        #     assert len(servs) > 0, "no services fetched"
        #     assert len(chars) > 0, "fetched characters are empty"
        #
        #     char_path, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
        #         services=servs,
        #         service_uid=service_uid,
        #         char_uid=char_uid)
        #     assert char_path, "characters are empty"
        #     assert len(char_props) > 0, "length of characters is 0"
        #
        #     self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        #
        #     # subscribe to notifications
        #     self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        #     self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path,
        #                                                                                  char_uid=char_uid)
        #
        #     # sw = Stopwatch()
        #     # while sw.elapsed_sec < 60:
        #     self.ble_dut.interfaces.bluetooth.ble_notify_custom_value(data=data)
        #     time.sleep(5)
        #     logger().info("Checking connection status of BLE")
        #     state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        #     state_int = int(state) if state.isdigit() else -1
        #     assert state_int == BLEDeviceState.Connected, "DUT BLE device is not in connected state"
        #     # unsubscribe to notifications
        #     self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        #     self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        #     time.sleep(1)
        #
        #     logger().info("======= validate data")
        #     notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        #
        #     logger().info(notifications)
        #     assert len(notifications) > 0, "received data is empty"
        #     assert notifications[0] == data, "failed to fetch data"
        #
        #     # logger().info("======= disconnecting from dut")
        #     # ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
        #     self.ble_client.interfaces.bluetooth.close()

        if self.test_case == "198668":
            logger().info(f"Advertising the DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising(timeout=20)
            self.sl_collections.scan_and_connect_from_remote(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                             ble_dut_address=self.ble_dut_address,
                                                             ble_pairing=self.ble_pairing)

    def ble_disconnect(self, disconnect_from="remote"):
        self.sl_collections.ble_disconnect(wifi_dut=self.wifi_dut, ble_client=self.ble_client, ble_dut_address=self.ble_dut_address,
                                           disconnect_from=disconnect_from, ble_client_address=self.ble_client_address)


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.DNSClient | Si91xTCPIPFeatureBitMap.HTTPClient,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                                  | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
            "custom_features": Si91xCustomFeatureBitMap.Default,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ble_features": Si91xBLEFeatureBitMap.Default | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        }
    )
]


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
def test_wifi_sdk_wlan_connect_11ax_ble_connect_with_diff_int_c198664(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, wifi_client, sniffer_filter):
    """Verify the WLAN connection with 11ax mode and BLE Connection as Slave using different BLE connection intervals"""

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         test_case="198664")

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_client=wifi_client, wifi_sniffer=wifi_sniffer,
                                           sl_collections=sl_collections, sniffer_filter=sniffer_filter)
        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()


# @pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
# @pytest.mark.end_state("wifi_dut",
#                        wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
# @pytest.mark.config('wifi_access_point',
#                     wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.TCP])
# @pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
# def test_wifi_sdk_wlan_tcp_tx_with_11ax_ble_connect_master_c198667(
#         wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
#         ble_dut, protocol, net_perf_client, traffic, qos):
#     """Verify the WLAN TCP Tx data transfer with 11ax AP when BLE Connection as Master and BLE Notifications & DLE
#     enabled"""
#
#     try:
#         test_name = request.node.name
#
#         logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
#         wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
#         wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")
#
#         ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
#                                          ble_dut=ble_dut, test_case="198667")
#
#         wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
#                                            wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
#                                            sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
#                                            protocol=protocol, net_perf_client=net_perf_client, test_case="198667")
#
#         wifi_obj.start()
#         wifi_obj.wait_for_exit()
#         ble_obj.start()
#         ble_obj.wait_for_exit()
#         wifi_sniffer.interfaces.capture.stop_capture()
#         logger().info("Stop the Sniffer")
#
#     except Exception as Ex:
#         sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.start_state("wifi_dut", "wifi_sniffer", wifi=['init', 'ap_enabled'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated", "ble_stop_adv"])
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": 'gnbax', "security": 'WPA2', "passphrase": 'thisisatestnetwork'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("traffic, qos", [('0xc8', 0)])
def test_wifi_sdk_wlan_tcp_rx_with_11ax_ble_connect_slave_smp_enable_c198668(
        wifi_sniffer, wifi_access_point, wifi_dut, ble_client, request, sl_collections, sniffer_filter, wifi_client,
        ble_dut, protocol, net_perf_client, traffic, qos):

    """Verify the WLAN TCP Rx data transfer with 11ax AP when BLE Connection as Slave with SMP Enabled"""

    try:
        test_name = request.node.name

        logger().info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{test_name}")

        ble_obj = BleThreadFunctionality(wifi_dut=wifi_dut, ble_client=ble_client, sl_collections=sl_collections,
                                         ble_dut=ble_dut, ble_pairing=1, test_case="198668")

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections, qos=qos,
                                           sniffer_filter=sniffer_filter, wifi_client=wifi_client, traffic=traffic,
                                           protocol=protocol, net_perf_client=net_perf_client, test_case="198668")

        ble_obj.start()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.wait_for_exit()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop the Sniffer")
        ble_client.interfaces.bluetooth.close()
        ble_obj.ble_disconnect()
        wifi_obj.sniffer_validation()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
