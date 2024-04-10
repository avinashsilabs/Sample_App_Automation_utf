import pytest
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xTCPIPFeatureBitMap, Si91xExtTCPIPFeatureBitMap, \
    Si91xFeatureBitMap, Si91xConfigFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xCustomFeatureBitMap
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.sl_status import SLStatus

"""The testcases added in this file run below test steps for SOC
        1. Configure the DUT in wlan coex mode for 2.4Ghz
        2. Start the sniffer before connection
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Verify the MDNS feature
        6. 3 Negative Test Cases 
    setup requirement:
        1. SOC
        2. NUC
        3. Raspberry PI
        4. Access Point(Third Party AP's)
    
    Author: Saurabh Sharma
        
"""


def logger():
    return get_logger(__name__)


class WifiThreadFunctionality(ThreadBase):
    def __init__(self, wifi_sniffer=None, wifi_dut=None, wifi_access_point=None, wifi_client=None, sl_collections=None,
                 sniffer_filter=None, test_case=None, capture_filename=None):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.sl_collections = sl_collections
        self.sniffer_filter = sniffer_filter
        self.device_ip = None
        self.dut_addr = None
        self.iperf_throughput = None
        self.test_case = test_case
        self.capture_filename = capture_filename

    def run(self):
        try:
            logger().info(f"Start sniffer capture on channel {self.wifi_access_point.interfaces.wifi.channel}")
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.capture_filename}")

            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=0, scan_interval=4,
                                                                          beacon_missed_count=40,
                                                                          first_time_retry_enable=0)

            self.dut_addr = self.sl_collections.join_to_wifi_network(self.wifi_dut, self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated)
        except Exception as Ex:
            self.sl_collections.exception_handling(wifi_dut=self.wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPServer,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mdns_neg_without_sel_feature_C19006(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, request):

    """Check whether DUT is giving error or not when issue MDNS init command without selecting the feature in
       opermode command."""

    try:
        capture_filename = request.node.name

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           capture_filename=capture_filename)
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.mdns_init(expected_status=SLStatus.SL_STATUS_SI91X_FEATURE_NOT_ENABLED)

        logger().info("******* DUT sent error code 0x1ff74 when MDNS feature is not enabled which is expected *******")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPServer | Si91xTCPIPFeatureBitMap.mDNS,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mdns_neg_port_already_in_use_C19007(wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, request):

    """Check whether DUT is giving an error or not when issue MDNS init command when udp socket is opened at 5353."""
    try:
        local_port = 5353
        capture_filename = request.node.name

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           capture_filename=capture_filename)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        sock = wifi_dut.interfaces.wifi.Asyncsocket(stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")

        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr['device_ip'], server_port=local_port,
                                      asynch=1)

        wifi_dut.interfaces.wifi.mdns_init()
        wifi_dut.interfaces.wifi.mdns_add_interface()
        wifi_dut.interfaces.wifi.mdns_register_service(expected_status=SLStatus.SL_STATUS_SI91X_PORT_UNAVAILABLE)

        logger().info("******* DUT sent error code 0x1bb23 when port is not available which is expected *******")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | Si91xTCPIPFeatureBitMap.HTTPServer | Si91xTCPIPFeatureBitMap.mDNS,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "bt_features": 0,
        "ble_features": 0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
def test_wifi_sdk_mdns_neg_multicast_socket_in_open_state_C19008(
        wifi_sniffer, wifi_access_point, wifi_dut, sl_collections, request, multicast_client):

    """Check whether DUT is giving error or not when issue MDNS init command after any multicast group is added."""
    try:
        capture_filename = request.node.name

        wifi_obj = WifiThreadFunctionality(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                                           wifi_sniffer=wifi_sniffer, sl_collections=sl_collections,
                                           capture_filename=capture_filename)
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        ip_version, ttl, multicast_mac, multicast_ip, device_port, server_port, buffer_length, no_of_pkts = multicast_client.interfaces.multicast.multicast_params()

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address()
        wifi_dut.interfaces.wifi.mdns_init()
        wifi_dut.interfaces.wifi.mdns_add_interface()
        wifi_dut.interfaces.wifi.mdns_register_service(
            expected_status=SLStatus.SL_STATUS_SI91X_MULTICAST_NO_ENTRIES_FOUND)

        logger().info("DUT sent error code 0x1bb17 when no more entries found for MULTICAST which is expected")
        logger().info("Stop the sniffer")
        wifi_sniffer.interfaces.capture.stop_capture()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
