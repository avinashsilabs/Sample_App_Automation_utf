import string
from typing import Dict
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xPowerSaveModes,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xPowerSaveProcedureTypes,
)
import time
import random
import string
import pytest
import re
from utf.utils import get_tls_certificate_dir
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from typing import Union
# from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap
from datetime import datetime
import uuid
from utf.interfaces.wifi import WlanError


def logger():
    return get_logger(__name__)


""" 
    setup requirement: DUT(RS9116), EFR32, Raspberry PI4, Access Point, Sniffer(NUC)
    Description : Websocket testcases
    Reported by : CG-Team,Anusha
"""


def text_generator(size=50):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


class WebsocketEventHandler:
    """
    Class to handle Websocket Server - connect,disconnect,data transfer.
    """

    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = ""

    def on_ws_client_connected(self, client: dict):
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        logger().info(f"what is the message getting received {message} ")
        self.message_received = message
        logger().info(f"received message {len(self.message_received)}")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
@pytest.mark.http_server("raspi_lighttpd")
def test_wifi_sdk_web_socket_C37479(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                    sl_collections):
    """
    Websocket functionality check(open , send_data ,close)
    """
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_web_socket_C37479'

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.connect_to_websocket_server(0, http_server.interfaces.http, server_port=80,
                                                             local_port=5001)

        logger().info("connect_to_websocket_server")
        time.sleep(0.1)
        assert ws_handler.client_connected
        iter_count = 30
        data = []
        for i in range(iter_count):
            data.append(text_generator(size=5))
            data_final = "".join(data)
            wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=129, message=data_final)
            logger().info("send_data_over_websocket")
            logger().info("opcode 129 sent")
            time.sleep(2)
            assert ws_handler.message_received == data_final

        wifi_dut.interfaces.wifi.websocket_close(0)
        logger().info("websocket_close")
        time.sleep(2)
        assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_wifi_sdk_module_sends_ping_request_or_not_when_web_socket_opened_by_giving_opcode_9_C19345(wifi_dut,
                                                                                                    wifi_access_point,
                                                                                                    wifi_sniffer,
                                                                                                    http_server,
                                                                                                    sl_collections):
    """
    Open websocket by enabling opcode 9 and check if module sends ping request
    """
    try:
        validation = True
        http_server.interfaces.http.interface = "eth0"
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_module_sends_ping_request_or_not_when_web_socket_opened_by_giving_opcode_9_C19345'
        sock = 0
        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='capture_filename')

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network(wifi_dut, wifi_access_point, power_save=True,
                                                     mode='power_save_low_latency',
                                                     ping_count=10, retry_count=1)

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80,
                                                             local_port=5001)
        time.sleep(0.1)
        assert ws_handler.client_connected
        iter_count = 30
        for i in range(iter_count):
            wifi_dut.interfaces.wifi.send_data_over_websocket(sock, opcode=137, message="!")
            logger().info("opcode 137 sent")
            time.sleep(2)

        wifi_dut.interfaces.wifi.websocket_close(sock)
        logger().info("websocket_close")
        time.sleep(2)
        assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["websocket"],
                                    capture_filename, ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_wifi_sdk_web_socket_close_functionality_using_websocketclose_API_C19341(wifi_dut, wifi_access_point,
                                                                                 wifi_sniffer,
                                                                                 http_server,
                                                                                 sl_collections):
    """
    Verify Web socket close functionality using 'websocket_close' API
    """
    try:
        validation = True
        rejoin_max = 10
        scan_interval = 6
        beacon_missedcount = 40
        first_time_retry = 0
        timeout = 10
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_web_socket_close_functionality_using_websocketclose_API_C19341'
        sock = 0

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80,
                                                             local_port=5001)

        logger().info("connect_to_websocket_server")
        time.sleep(0.1)
        assert ws_handler.client_connected
        iter_count = 30
        data = []
        for i in range(iter_count):
            data.append(text_generator(size=5))
            data_final = "".join(data)
            wifi_dut.interfaces.wifi.send_data_over_websocket(sock, opcode=129, message=data_final)
            logger().info("send_data_over_websocket")
            logger().info("opcode 129 sent")
            time.sleep(2)
            assert ws_handler.message_received == data_final

        wifi_dut.interfaces.wifi.websocket_close(sock)
        logger().info("websocket_close")
        time.sleep(2)
        assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["websocket"],
                                    capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point',
                    wifi={"standard": '11n', "security": 'WPA2', "ssid": 'TEST', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_wifi_sdk_web_socket_opcode8_socketclose_C19342(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                        sl_collections):
    """
    Verify send data over web socket by enabling opcode 8 in send command,
    check socket if close functionality is working or not.
    """
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_web_socket_opcode8_socketclose_C19342'
        sock = 0

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80,
                                                             local_port=5001)

        logger().info("connect_to_websocket_server")

        time.sleep(0.1)
        assert ws_handler.client_connected
        iter_count = 30
        data = []
        for i in range(iter_count):
            data.append(text_generator(size=5))
            data_final = "".join(data)
            wifi_dut.interfaces.wifi.send_data_over_websocket(sock, opcode=129, message=data_final)
            logger().info("send_data_over_websocket")
            logger().info("opcode 129 sent")
            time.sleep(2)
            assert ws_handler.message_received == data_final

        wifi_dut.interfaces.wifi.send_data_over_websocket(sock, opcode=8, message="!")
        logger().info("opcode 8 sent")
        time.sleep(0.1)

        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["websocket"],
                                    capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_wifi_sdk_rx_over_websocket_disable_finbit_C19344(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                          sl_collections):
    """
    Verify RX over web socket when it receives data by not enabling FIN bit in web socket header
    """
    try:
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_rx_over_websocket_disable_finbit_C19344'
        sock = 0

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80,
                                                             local_port=5001)

        logger().info("connect_to_websocket_server")
        time.sleep(0.1)
        assert ws_handler.client_connected

        iter_count = 30
        data = []
        for i in range(iter_count):
            data.append(text_generator(size=5))
            data_final = "".join(data)
            wifi_dut.interfaces.wifi.send_data_over_websocket(sock, opcode=1, message=data_final)
            logger().info("send_data_over_websocket")
            logger().info("opcode 1 sent")
            time.sleep(2)
            assert ws_handler.message_received == data_final

        logger().info("websocket_close")
        wifi_dut.interfaces.wifi.websocket_close(sock)
        time.sleep(2)
        assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ca_cert": ["ca-chain.cert.pem"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_wifi_sdk_max_websocket_over_ssl_C19346(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                 sl_collections):
    """
    Verify max number of web sockets over SSL
    """
    try:
        validation = True
        timeout = 10
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_max_websocket_over_ssl_C19346'

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )

        port = 5001
        for sockets in range(2):
            wifi_dut.interfaces.wifi.connect_to_websocket_server(2, http_server.interfaces.http, server_port=443,
                                                                 local_port=port)
            logger().info(f"connect_to_websocket_server{sockets}")
            time.sleep(0.1)
            assert ws_handler.client_connected
            iter_count = 30
            data = []
            for j in range(iter_count):
                data.append(text_generator(size=5))
                data_final = "".join(data)
                wifi_dut.interfaces.wifi.send_data_over_websocket(sockets, opcode=129, message=data_final)
                logger().info(f"send_data_over_websocket{sockets}")
                logger().info("opcode 129 sent")
                time.sleep(3)
                assert ws_handler.message_received == data_final
            port = port + 1
            time.sleep(10)

        for sockets in range(2):
            wifi_dut.interfaces.wifi.websocket_close(sockets)
            logger().info("websocket_close")
            time.sleep(2)
            assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "config_features": Si91xConfigFeatureBitMap.EnahanceMaxPsp | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_wifi_sdk_tx_max_data_length_over_websocket_C19340(wifi_dut, wifi_access_point, wifi_sniffer, http_server,
                                                           sl_collections):
    """
    Verify Tx over web socket with maximum data length.
    """
    try:
        validation = True
        timeout = 10
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_tx_max_data_length_over_websocket_C19340'
        sock = 0

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )
        wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80,
                                                             local_port=5001)

        logger().info("connect_to_websocket_server")
        time.sleep(0.1)
        assert ws_handler.client_connected

        iter_count = 5
        for iter in range(iter_count):
            data_final = (text_generator(size=1450))
            wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=129, message=data_final)
            logger().info("send_data_over_websocket")
            logger().info("opcode 1 sent")
            time.sleep(2)
            assert ws_handler.message_received == data_final

        logger().info("websocket_close")
        wifi_dut.interfaces.wifi.websocket_close(sock)
        time.sleep(2)
        assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'

        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.DualBluetoothBLE,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower | Si91xExtCustomFeatureBitMap.Feature384kBMemoryMode | Si91xExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE,
        "ca_cert": ["ca-chain.cert.pem"],
    }
)
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_wifi_sdk_tx_over_web_socket_over_SSL_with_maximum_data_length_C19343(wifi_dut, wifi_access_point, wifi_sniffer,
                                                                              http_server,
                                                                              sl_collections):
    """
    Verify Tx over web socket over SSL with maximum data length.
    """
    try:
        validation = True
        timeout = 10
        channel = wifi_access_point.interfaces.wifi.channel
        capture_filename = 'test_tx_over_web_socket_over_SSL_with_maximum_data_length_C19343'

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        result = sl_collections.join_to_wifi_network_with_rejoin(wifi_dut, wifi_access_point, ping_count=10,
                                                                 retry_count=3, rejoin_parms=[10, 6, 40, 0])
        device_ip, dut_mac_address = result['device_ip'], result['dut_mac_address']

        ws_handler = WebsocketEventHandler()
        http_server.interfaces.http.set_fn_on_websocket_client_connected(
            ws_handler.on_ws_client_connected
        )
        http_server.interfaces.http.set_fn_on_websocket_client_disconnected(
            ws_handler.on_ws_client_disconnected
        )
        http_server.interfaces.http.set_fn_on_websocket_message_received(
            ws_handler.on_ws_message_received
        )

        port = 5001
        wifi_dut.interfaces.wifi.connect_to_websocket_server(2, http_server.interfaces.http, server_port=443,
                                                             local_port=port)
        time.sleep(0.1)
        assert ws_handler.client_connected
        iter_count = 5
        for iter in range(iter_count):
            data_final = text_generator(size=1362)
            wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=129, message=data_final)
            logger().info(f"send_data_over_websocket")
            logger().info("opcode 129 sent")
            time.sleep(3)
            assert ws_handler.message_received == data_final

        wifi_dut.interfaces.wifi.websocket_close(0)
        logger().info("websocket_close")
        time.sleep(2)
        assert ws_handler.client_disconnected

        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f"(wlan.ta == {result['dut_mac_address']}) and (wlan.fc.type_subtype == 0x001a)"

        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter2 = f"!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or " \
                         f"(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or " \
                         f"(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {result['dut_mac_address']})"

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                             'in sniffer'
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

        sl_collections.packet_check(wifi_sniffer, decryption_key, result['dut_mac_address'], ["http"], capture_filename,
                                    ap_bssid, mode=0, handshake_pkt=False, get_cipher=False)
    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)