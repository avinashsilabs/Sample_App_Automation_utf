import pytest
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xJoinFeatureBitMap, \
    Si91xPowerSaveProcedureTypes, Si91xWebSocketParms
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
import random
import string
from typing import Union
import time
from utf.utils.stopwatch import Stopwatch


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. Soc board
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify Websocket functionality

    Author: Vinod 

"""


class WebsocketEventHandler:
    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = ""

    def on_ws_client_connected(self, client: dict):
        # logger().info(f"what is the message getting received 1 ")
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        # logger().info(f"what is the message getting received 2")
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        logger().info(f"what is the message getting received {message} ")
        self.message_received = message
        logger().info(f"received message {len(self.message_received)}")


def text_generator(size=1000):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def logger():
    return get_logger(__name__)


def wifi_dut_marker(ca_cert=None, client_cert=None, client_key=None, tcpip_feat=0, ext_custom_feat=0, ext_tcpip_feat=0):
    """
    Common method to generate wifi_dut marker for pytest.mark.config decorator.
    """
    config = {
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | tcpip_feat,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | ext_tcpip_feat,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | ext_custom_feat,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,

        }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert

    if client_key:
        config["client_key"] = client_key
    return pytest.mark.config("wifi_dut", wifi=config)


class WLanJoinThread(ThreadBase):
    """This function is responsible for wi-fi connectivity"""

    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, ping_count=None, test_case=None,
                 sl_collections=None, sniffer_filter=None, power_save=None, ap_mac_address=None,
                 http_server=None, capture_filename=None, wifi_client=None, switch=None, websocket_iter_count=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.ping_count = ping_count
        self.wifi_sniffer = wifi_sniffer
        self.sl_collections = sl_collections
        self.test_case = test_case
        self.sniffer_filter = sniffer_filter
        self.dut_addr = None
        self.power_save = power_save
        self.ap_mac_address = ap_mac_address
        self.http_server = http_server
        self.capture_filename = capture_filename
        self.wifi_client = wifi_client
        self.switch = switch
        self.websocket_iter_count = websocket_iter_count

    def run(self):
        try:
            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.capture_filename)
            time.sleep(3)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated,
                                                                     channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                     retry_count=3)
            self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
            ws_handler = WebsocketEventHandler()
            self.http_server.interfaces.http.set_fn_on_websocket_client_connected(
                ws_handler.on_ws_client_connected
                )
            self.http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
                ws_handler.on_ws_client_disconnected
                )
            self.http_server.interfaces.http.set_fn_on_websocket_message_received(
                ws_handler.on_ws_message_received
                )

            host_name = "example.com"
            sw = Stopwatch()
            iteration = 0
            while sw.elapsed_sec < self.websocket_iter_count:
                iteration = iteration + 1
                logger().info(f"Iteration count -> {iteration}")
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, host_name,
                                                             "/websocket",
                                                             80, 5001)

                self.wifi_dut.interfaces.wifi.websocket_connect(timeout=60)
                logger().info("connect_to_websocket_server")
                time.sleep(0.1)
                assert ws_handler.client_connected
                data = text_generator(size=50)
                logger().info("send_data_over_websocket")
                self.wifi_dut.interfaces.wifi.websocket_send(
                    opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                    higher_data_len=0, data=data)
                time.sleep(2)
                logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                # assert ws_handler.message_received == data, f"data sent by DUT and received on websocket server are
                # not same on iteration count {iteration}"
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
                time.sleep(1)
            logger().info("Stopping sniffer capture")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.leave()
            self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                filter_name="power_mgmt_bit")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=self.power_save_filter)['packet_count'] > 0, \
                "Unable to find NULL-Data frame packets with power save bit = 1"
            return


        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C687539')
def test_wifi_sdk_websocket_connection_close_in_loop_c687539(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                             utf_constants,
                                                             request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity and close functionality in loop for 12 hours
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        websocket_iter_count = utf_constants.get("websocket_long_run_test_time_duration")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='C687539',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename,
                                  websocket_iter_count=websocket_iter_count)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
