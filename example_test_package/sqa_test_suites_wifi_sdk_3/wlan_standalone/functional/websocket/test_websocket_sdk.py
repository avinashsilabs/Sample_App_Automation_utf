import pytest
import re
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import Si91xCoexMode, Si91xFeatureBitMap, Si91xConfigFeatureBitMap, \
    Si91xOperatingMode, Si91xTCPIPFeatureBitMap, Si91xCustomFeatureBitMap, Si91xExtCustomFeatureBitMap, \
    Si91xExtTCPIPFeatureBitMap, Si91xPowerSaveModes, Si91xJoinFeatureBitMap, \
    Si91xPowerSaveProcedureTypes, Si91xWebSocketParms
from utf.utils.thread_base import ThreadBase
from utf.utf_config import UtfConfig
from utf_wiseconnect_3.tests.sl_status import SLStatus
import random
import string
from typing import Union
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import ipaddress
from threading import Thread
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
                 http_server=None, capture_filename=None, wifi_client=None, switch=None):
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

    def run(self):
        try:
            logger().info('\n*** Configuring Sniffer with WAP channel ***\n')
            self.wifi_sniffer.interfaces.capture.configure_interface(
                channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.capture_filename)
            time.sleep(3)
            if self.test_case == '687503':
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         ip_version='ipv6',
                                                                         ipv6_type="global",
                                                                         retry_count=3)
            elif self.test_case == '687502':
                self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                         ip_version='ipv6',
                                                                         wifi_access_point=self.wifi_access_point,
                                                                         associated=self.wifi_dut.interfaces.wifi.associated,
                                                                         channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                         retry_count=3)
            else:
                if self.test_case != "687276" and self.test_case != '688067':
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

            if self.test_case == '687502' or self.test_case == '687503':
                remote_ip = self.wifi_client.interfaces.wifi.get_ip_address(version=6)
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001, server_ip=remote_ip)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                iter_count = 10
                for i in range(iter_count):
                    data = text_generator(size=1000)
                    address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                    self.wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)
                    self.wifi_dut.interfaces.wifi.websocket_send(
                        opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                        higher_data_len=1, address=address)
                    self.wifi_dut.interfaces.wifi.memory_free(address)
                    time.sleep(2)
                    logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                    # assert ws_handler.message_received == data
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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
            elif self.test_case == '19340':
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                iter_count = 10
                for i in range(iter_count):
                    data = text_generator(size=1450)
                    address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                    self.wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)
                    self.wifi_dut.interfaces.wifi.websocket_send(
                        opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                        higher_data_len=1, address=address)
                    self.wifi_dut.interfaces.wifi.memory_free(address)
                    time.sleep(2)
                    logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                    # assert ws_handler.message_received == data
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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
            elif self.test_case == '688069':
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                iter_count = 10
                for i in range(iter_count):
                    data = text_generator(size=50)
                    self.wifi_dut.interfaces.wifi.websocket_send(
                        opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_BINARY | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                        higher_data_len=0, data=data)
                    time.sleep(2)
                    logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                    # assert ws_handler.message_received == data
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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
            elif self.test_case == '19343':
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             443, 5001, enable_tls=1)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                iter_count = 10
                for i in range(iter_count):
                    data = text_generator(size=1362)
                    address = self.wifi_dut.interfaces.wifi.allocate_memory(size=len(data) + 1)
                    self.wifi_dut.interfaces.wifi.load_memory(address=address, size=len(data), write_content=data)
                    self.wifi_dut.interfaces.wifi.websocket_send(
                        opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                        higher_data_len=1, address=address)
                    self.wifi_dut.interfaces.wifi.memory_free(address)
                    time.sleep(2)
                    logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                    # assert ws_handler.message_received == data
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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


            elif self.test_case == '19346':
                max_web_sockets = 2
                server_port = 443
                instance = 0
                for socket in range(0, max_web_sockets):
                    if socket == 0:
                        client_port = 5001
                    else:
                        client_port = 5002
                        instance = 1
                    self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                                 "/websocket",
                                                                 server_port, client_port=client_port, enable_tls=1,
                                                                 instance=instance)
                    self.wifi_dut.interfaces.wifi.websocket_connect(instance=instance)

                time.sleep(0.1)
                assert ws_handler.client_connected
                iter_count = 20

                for i in range(iter_count):
                    data = text_generator(size=50)
                    if (i % 2) == 0:
                        instance = 0
                    else:
                        instance = 1
                    self.wifi_dut.interfaces.wifi.websocket_send(
                        opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                        higher_data_len=0, data=data, instance=instance)
                    time.sleep(2)
                    logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                    assert ws_handler.message_received == data, "data sent by DUT and received on websocket server " \
                                                                "are not same "

                for socket in range(0, max_web_sockets):
                    if socket == 0:
                        instance = 0
                    if socket == 1:
                        instance = 1
                    self.wifi_dut.interfaces.wifi.websocket_close(instance=instance)
                    self.wifi_dut.interfaces.wifi.websocket_deinit(instance=instance)
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


            elif self.test_case == '19341' or self.test_case == '687497':
                if self.test_case == '19341':
                    host_name = "example.com"
                else:
                    host_name = text_generator(size=50)
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, host_name,
                                                             "/websocket",
                                                             80, 5001)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                data = text_generator(size=50)
                logger().info("send_data_over_websocket")
                self.wifi_dut.interfaces.wifi.websocket_send(
                    opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                    higher_data_len=0, data=data)
                time.sleep(2)
                logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                assert ws_handler.message_received == data, "Data sent by dut and received on the server is not matched"
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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
                if self.test_case == '19341':
                    opcode_8 = 0
                    dut_ip, dut_mac_address = self.dut_addr['device_ip'], self.dut_addr['dut_mac_address']
                    decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
                    ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                    websocket_capture_list = \
                        self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, dut_mac_address,
                                                                  ["websocket"],
                                                                  self.capture_filename, ap_bssid)['websocket']
                    for websocket in websocket_capture_list:
                        logger().info(f"websocket info {websocket[0]}")
                        # fetch DUT ip address
                        if websocket[2] == dut_ip:
                            # fetch websocket layer content from the sniffer capture fields
                            websocket_layer = websocket[0]
                            if re.search(".*Opcode: Connection Close", websocket_layer):
                                logger().info(f"DUT sent opcode-8 frame to close the websocket connection")
                                opcode_8 = opcode_8 + 1
                    assert opcode_8 != 0, "4-way handshake is not captured or DUT doesn't send opcode-8 frame to " \
                                          "close the websocket connection "
                return
            elif self.test_case == '19342':
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                data = text_generator(size=50)
                logger().info("send_data_over_websocket")
                self.wifi_dut.interfaces.wifi.websocket_send(
                    opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                    higher_data_len=0, data=data)
                time.sleep(2)
                logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                assert ws_handler.message_received == data
                self.wifi_dut.interfaces.wifi.websocket_send(
                    opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_CLOSE | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                    higher_data_len=0, data=data)
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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

                opcode_8 = 0
                dut_ip, dut_mac_address = self.dut_addr['device_ip'], self.dut_addr['dut_mac_address']
                decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
                ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                websocket_capture_list = \
                    self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, dut_mac_address,
                                                              ["websocket"],
                                                              self.capture_filename, ap_bssid)['websocket']
                for websocket in websocket_capture_list:
                    logger().info(f"websocket info {websocket[0]}")
                    # fetch DUT ip address
                    if websocket[2] == dut_ip:
                        # fetch websocket layer content from the sniffer capture fields
                        websocket_layer = websocket[0]
                        if re.search(".*Opcode: Connection Close", websocket_layer):
                            logger().info(f"DUT sent opcode-8 frame to close the websocket connection")
                            opcode_8 = opcode_8 + 1
                assert opcode_8 != 0, "4-way handshake is not captured or DUT doesn't send opcode-8 frame to close " \
                                      "the websocket connection "
                return

            elif self.test_case == '687979':
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                data = text_generator(size=50)
                logger().info("send_data_over_websocket")
                self.wifi_dut.interfaces.wifi.websocket_send(
                    opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                    higher_data_len=0, data=data)
                time.sleep(2)
                logger().info(f"data received on websocket server ->{ws_handler.message_received}")

                def close_http_server(http_server, run_time):
                    logger().info(f"Close http server after {run_time} seconds")
                    time.sleep(run_time)
                    http_server.interfaces.http.stop_server()

                thread = Thread(target=close_http_server, args=(self.http_server, 10), )
                thread.start()
                for count in range(0, 50):
                    data = text_generator(size=50)
                    logger().info("send_data_over_websocket")
                    try:
                        self.wifi_dut.interfaces.wifi.websocket_send(
                            opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                            higher_data_len=0, data=data)
                        time.sleep(2)
                        logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                    except:
                        logger().info(f"The DUT is unable to send data over the WebSocket")
                        break

                time.sleep(1)
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                remote_terminate = 0
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.WEBSOCKET_REMOTE_TERMINATE_EVENT:
                        remote_terminate = 1
                assert remote_terminate == 1, "Remote terminate event not received"

                logger().info(
                    f"DUT received a remote termination event when the WebSocket server closed while the DUT was "
                    f"sending data which is expected")

                # self.wifi_dut.interfaces.wifi.websocket_close()
                # self.wifi_dut.interfaces.wifi.websocket_deinit()
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
            elif self.test_case == '19345':
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001)
                self.wifi_dut.interfaces.wifi.websocket_connect()
                time.sleep(0.1)
                assert ws_handler.client_connected
                data = text_generator(size=50)
                logger().info("send_data_over_websocket")
                self.wifi_dut.interfaces.wifi.websocket_send(
                    opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                    higher_data_len=0, data=data)
                time.sleep(2)
                logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                assert ws_handler.message_received == data, "Data sent by DUT and received on Websocket server is not " \
                                                            "same "
                self.wifi_dut.interfaces.wifi.websocket_send(opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_PING,
                                                             higher_data_len=0, data=data)
                self.wifi_dut.interfaces.wifi.websocket_close()
                self.wifi_dut.interfaces.wifi.websocket_deinit()
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
                opcode_9 = 0
                dut_ip, dut_mac_address = self.dut_addr['device_ip'], self.dut_addr['dut_mac_address']
                decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
                ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
                websocket_capture_list = \
                    self.sl_collections.ssl_packet_decryption(self.wifi_sniffer, decryption_key, dut_mac_address,
                                                              ["websocket"],
                                                              self.capture_filename, ap_bssid)['websocket']
                for websocket in websocket_capture_list:
                    logger().info(f"websocket info {websocket[0]}")
                    # fetch DUT ip address
                    if websocket[2] == dut_ip:
                        # fetch websocket layer content from the sniffer capture fields
                        websocket_layer = websocket[0]
                        if re.search(".*Opcode: Ping", websocket_layer):
                            logger().info(f"DUT sent opcode-9(ping) websocket frame")
                            opcode_9 = opcode_9 + 1
                assert opcode_9 != 0, "4-way handshake is not captured or DUT doesn't send opcode-9 frame->websocket " \
                                      "ping "
                return
            elif self.test_case == '687274':
                invalid_server = "192.168.30.50"
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             "/websocket",
                                                             80, 5001,
                                                             server_ip=invalid_server)
                self.wifi_dut.interfaces.wifi.websocket_connect(
                    expected_status=SLStatus.SL_WEBSOCKET_ERR_SOCKET_CONNECT, timeout=40)
                logger().info(
                    f"Websocket connection is failed with the error {SLStatus.SL_WEBSOCKET_ERR_SOCKET_CONNECT}(-3) "
                    f"when server is not responding which is expected")
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
            elif self.test_case == '687499':
                host_name = text_generator(size=52)
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, host_name,
                                                             "/websocket",
                                                             80, 5001,
                                                             expected_status=SLStatus.SL_WEBSOCKET_ERR_INVALID_PARAMETER)
                logger().info(
                    f"websocket init is failed with the error {SLStatus.SL_WEBSOCKET_ERR_INVALID_PARAMETER}(-8) when "
                    f"host_name given is more than 52 bytes which is expected")

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

            elif self.test_case == '687500':
                resource_name = text_generator(size=52)
                self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                             resource_name,
                                                             80, 5001,
                                                             expected_status=SLStatus.SL_WEBSOCKET_ERR_INVALID_PARAMETER)
                logger().info(
                    f"websocket init is failed with the error {SLStatus.SL_WEBSOCKET_ERR_INVALID_PARAMETER}(-8) when "
                    f"resource name given is more than 52 bytes which is expected")

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
            elif self.test_case == '687276':
                host_name = "example.com"
                for count in range(0, 10):
                    self.logger.info(
                        f"*************************ITERATION COUNT-> {count}****************************************")
                    self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(
                        join_feature_bitmap=Si91xJoinFeatureBitMap.MgmtFrameProtectionCapable |
                                            Si91xJoinFeatureBitMap.MgmtFrameProtectionRequired)
                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             retry_count=3)
                    self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, host_name,
                                                                 "/websocket",
                                                                 80, 5001)
                    self.wifi_dut.interfaces.wifi.websocket_connect()
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
                    assert ws_handler.message_received == data, "Data sent by DUT and received on Websocket server is " \
                                                                "not same "
                    self.wifi_dut.interfaces.wifi.websocket_close()
                    self.wifi_dut.interfaces.wifi.websocket_deinit()
                    self.wifi_dut.interfaces.wifi.leave()
                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                    filter_name="power_mgmt_bit")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=self.power_save_filter)['packet_count'] > 0, \
                    "Unable to find NULL-Data frame packets with power save bit = 1"
                return
            elif self.test_case == '687275' or self.test_case == '37479':
                host_name = "example.com"
                for count in range(0, 10):
                    if self.test_case == '687275':
                        self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, host_name,
                                                                     "/websocket",
                                                                     80, 5001)
                    else:
                        self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, host_name,
                                                                     "/websocket",
                                                                     443, 5001, enable_tls=1)
                    self.wifi_dut.interfaces.wifi.websocket_connect()
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
                    assert ws_handler.message_received == data, "Data sent by DUT and received on the Websocket " \
                                                                "server is not same "
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

            elif self.test_case == '688067':
                def ap_switch(switch, ap_turn_off_time, start_delay):
                    time.sleep(start_delay)
                    logger().info(f"Turn off AP for {ap_turn_off_time} seconds")
                    switch.interfaces.pdu_switch.turn_off(delay=10)
                    time.sleep(ap_turn_off_time)

                for count in range(0, 2):
                    self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=20,
                                                                                  scan_interval=6,
                                                                                  beacon_missed_count=40,
                                                                                  first_time_retry_enable=0)
                    self.wifi_dut.interfaces.wifi.associated = False
                    self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                             wifi_access_point=self.wifi_access_point,
                                                                             associated=self.wifi_dut.interfaces.wifi.associated,
                                                                             channel=self.wifi_access_point.interfaces.wifi.channel,
                                                                             retry_count=3)

                    self.wifi_dut.interfaces.wifi.websocket_init(self.http_server.interfaces.http, "example.com",
                                                                 "/websocket",
                                                                 80, 5001)
                    self.wifi_dut.interfaces.wifi.websocket_connect()
                    time.sleep(0.1)
                    assert ws_handler.client_connected

                    ap_turn_off_time = 150
                    start_delay = 30
                    thread = Thread(target=ap_switch, args=(self.switch, ap_turn_off_time, start_delay), )
                    thread.start()
                    sw = Stopwatch()
                    end_time = 300
                    rejoin_error_event = 0
                    logger().info(f"rejoin error event before turning off AP {rejoin_error_event}")
                    while sw.elapsed_sec < end_time:
                        try:
                            data = text_generator(size=50)
                            logger().info("send_data_over_websocket")
                            self.wifi_dut.interfaces.wifi.websocket_send(
                                opcode=Si91xWebSocketParms.SL_WEBSOCKET_OPCODE_TEXT | Si91xWebSocketParms.SL_WEBSOCKET_FIN_BIT,
                                higher_data_len=0, data=data)
                            time.sleep(2)
                            logger().info(f"data received on websocket server ->{ws_handler.message_received}")
                            assert ws_handler.message_received == data, "data sent by DUT and received on websocket " \
                                                                        "server is " \
                                                                        "not " \
                                                                        "matched"
                        except:
                            logger().info(f"Unable to send data over Websocket as AP is turned off. wait for 20 sec")
                            time.sleep(20)
                            events = self.wifi_dut.interfaces.wifi.get_async_events()

                            for event in events:
                                if event.event_type == AsyncEventIdentifiers.REJOIN_EVENT:
                                    rejoin_error_event = 1
                                    logger().info(f"rejoin error event after turning off AP {rejoin_error_event}")
                                    break
                    logger().info(f"Turn on AP")
                    self.switch.interfaces.pdu_switch.turn_on(delay=60)
                    assert rejoin_error_event == 1, "Rejoin failure event not received"

                # self.wifi_dut.interfaces.wifi.websocket_close()
                # self.wifi_dut.interfaces.wifi.websocket_deinit()
                logger().info("Stopping sniffer capture")
                self.wifi_sniffer.interfaces.capture.stop_capture()
                time.sleep(5)
                # self.wifi_dut.interfaces.wifi.leave()
                self.power_save_filter = self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_addr['dut_mac_address'], da_addr=self.ap_mac_address,
                    filter_name="power_mgmt_bit")
                assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                    packet_filter1=self.power_save_filter)['packet_count'] > 0, \
                    "Unable to find NULL-Data frame packets with power save bit = 1"
        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case thread: {str(e)} ****\n\n")
            raise e

    @classmethod
    def random_ipv6_addr(cls, network):
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


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_send_max_data_c19340(wifi_dut, wifi_access_point, wifi_sniffer, http_server, utf_constants,
                                                 request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connection and data transfer functionality
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='19340',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_close_c19341(wifi_dut, wifi_access_point, wifi_sniffer, http_server, utf_constants,
                                         request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity and close functionality
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='19341',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_opcode_8_func_c19342(wifi_dut, wifi_access_point, wifi_sniffer, http_server, utf_constants,
                                                 request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity and close functionality when websocket frame is sent with opcode-8
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='19342',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_opcode_9_func_c19345(wifi_dut, wifi_access_point, wifi_sniffer, http_server, utf_constants,
                                                 request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity and websocket ping functionality
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='19345',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_connectivity_neg_c687274(wifi_dut, wifi_access_point, wifi_sniffer,
                                                     http_server, utf_constants,
                                                     request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket functionality when websocket server doesn't respond
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687274',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_connectivity_neg_c687499(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                     utf_constants,
                                                     request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket functionality when host name given is more than 51 bytes
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687499',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_connectivity_neg_c687500(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                     utf_constants,
                                                     request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket functionality when resource name given is more than 51 bytes
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")
    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687500',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_max_hostname_c687497(wifi_dut, wifi_access_point, wifi_sniffer, http_server, utf_constants,
                                                 request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity when maximum hostname length is given(50 bytes)
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687497',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_connection_close_in_loop_c687275(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                             utf_constants,
                                                             request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity and close functionality in loop
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687275',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_ssl_send_max_data_c19343(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                     utf_constants,
                                                     request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connection over ssl and data transfer functionality
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='19343',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 ext_tcpip_feat=Si91xExtTCPIPFeatureBitMap.THREE_SSL_SOCKET_SELECT,
                 )
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_ssl_max_websockets_c19346(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                      utf_constants,
                                                      request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connection and data transfer functionality over 2 websockets
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='19346',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 tcpip_feat=Si91xTCPIPFeatureBitMap.SSL,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_ssl_connect_disconnect_c37479(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                          utf_constants,
                                                          request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify Websocket over SSL connect and disconnect functionality
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='37479',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.skip()
@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_opcode2_c688069(wifi_dut, wifi_access_point, wifi_sniffer, http_server, utf_constants,
                                            request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify websocket connectivity and close functionality
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='688069',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_remote_terminate_c687979(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                     utf_constants,
                                                     request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify Websocket functionality after socket closed due to remote terminate event on Websocket
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687979',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "0",
                               "wan_ipv6_address": WLanJoinThread().random_ipv6_addr("2401:4900:1cb3::/48"),
                               "security": "Open"}
    )
@wifi_dut_marker(tcpip_feat=Si91xTCPIPFeatureBitMap.DHCPv6Client
                            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                            | Si91xTCPIPFeatureBitMap.DHCPv6Server,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_websocket_with_ipv6_stateless_c687503(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer,
                                                        http_server,
                                                        utf_constants,
                                                        request, sl_collections, sniffer_filter, wifi_client):
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687503',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename, wifi_client=wifi_client)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@pytest.mark.firmware_app("test_ipv6")
@pytest.mark.config(
    "wifi_access_point", wifi={"ipv6_state": "1",
                               "wan_ipv6_address": WLanJoinThread().random_ipv6_addr("2401:4900:1cb3::/48"),
                               "security": "Open"}
    )
@wifi_dut_marker(tcpip_feat=Si91xTCPIPFeatureBitMap.DHCPv6Client
                            | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP | Si91xTCPIPFeatureBitMap.IPv6Mode
                            | Si91xTCPIPFeatureBitMap.DHCPv6Server,
                 ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode)
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable"])
def test_wifi_sdk_websocket_with_ipv6_stateful_c687502(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer,
                                                       http_server,
                                                       utf_constants,
                                                       request, sl_collections, sniffer_filter, wifi_client):
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687502',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename, wifi_client=wifi_client)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker(
    ext_custom_feat=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode | Si91xExtCustomFeatureBitMap.IEEE802_11W)
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'sta_mode_ssid', "passphrase": '12345678', "security": 'WPA3',
                                               "protected_management_frame": "Capable", })
def test_wifi_sdk_sec_wpa3_websocket_connection_close_in_loop_c687276(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                      http_server,
                                                                      utf_constants,
                                                                      request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify Websocket connect and disconnect functionality in WPA3 security mode
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='687276',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)


@wifi_dut_marker()
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unassociated"])
def test_wifi_sdk_websocket_data_transfer_while_rejoin_688067(switch, wifi_dut, wifi_access_point, wifi_sniffer,
                                                              http_server,
                                                              utf_constants,
                                                              request, sl_collections, sniffer_filter):
    """
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify Websocket functionality second time after rejoin failure indication to DUT
    """
    capture_filename = request.node.name
    power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
    logger().info(f"\n **** Fetching user define power_save flag value = {power_save} from Harness file ****")

    ap_mac_address = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"\n **** AP MAC ADDRESS ={ap_mac_address} ****\n")

    try:
        ping_count = utf_constants.get("ping_count")
        wlan_obj = WLanJoinThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, wifi_sniffer=wifi_sniffer,
                                  sl_collections=sl_collections, sniffer_filter=sniffer_filter, test_case='688067',
                                  ping_count=ping_count, power_save=power_save, ap_mac_address=ap_mac_address,
                                  http_server=http_server, capture_filename=capture_filename, switch=switch)

        wlan_obj.start()
        wlan_obj.wait_for_exit()

    except Exception as EX:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=EX)
