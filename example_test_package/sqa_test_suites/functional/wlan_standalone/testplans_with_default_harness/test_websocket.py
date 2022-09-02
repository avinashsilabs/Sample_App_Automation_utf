import string
from typing import Dict
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    RS9116AsyncEventType,
    RS9116OperatingMode,
    DeviceConstants,
    RS9116JoinFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
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
def packet_check_pingpong(wifi_sniffer, logger, decryption_key: str, mac_address, print_layers: list,
                    capture_filename,
                    mode=0) -> Dict[str, int]:
    cipher_suite = []
    count = 0
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "websocket":
                http_layer = str(layer)
                if (re.search(".*Opcode: Ping",http_layer)):
                    logger().info(f"PING PACKET {http_layer}")
                elif (re.search(".*Opcode: Pong",http_layer)):
                    logger().info(f"PONG PACKET {http_layer}")

    return cipher_suite

def packet_check(wifi_sniffer, logger, decryption_key: str, mac_address, print_layers: list,
                    capture_filename,
                    mode=0) -> Dict[str, int]:
    cipher_suite = []
    count = 0
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {mac_address})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
            ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            #logger().info(f"LAYER NAME TO BE CHECKED {layer_name}")
            if layer_name == "http":
                http_layer = str(layer)
                logger().info(f"http layer {http_layer}")
    return cipher_suite

class WebsocketEventHandler:
    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = ""

    def on_ws_client_connected(self, client: dict):
        #logger().info(f"what is the message getting received 1 ")
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        #logger().info(f"what is the message getting received 2")
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        logger().info(f"what is the message getting received {message} ")
        self.message_received = message
        logger().info(f"received message {len(self.message_received)}")


# configure ping_count to ping dut
ping_count = 20


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        }
    )
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_web_socket_C37479(wifi_dut, wifi_access_point, wifi_sniffer, http_server):

    validation = True
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = 'test_web_socket_C37479'

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(0, http_server.interfaces.http, server_port=80, local_port=5001)

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

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                         'in sniffer'
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    websocket_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ["http"], capture_filename,
                                   mode=0)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        }
    )
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_module_sends_ping_request_or_not_when_web_socket_opened_by_giving_opcode_9_C19345(wifi_dut, wifi_access_point, wifi_sniffer, http_server):
    validation = True
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = 'test_module_sends_ping_request_or_not_when_web_socket_opened_by_giving_opcode_9_C19345'
    sock = 0
    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='capture_filename')

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80, local_port=5001)
    time.sleep(0.1)
    assert ws_handler.client_connected
    wifi_dut.interfaces.wifi.send_data_over_websocket(sock, opcode=137, message="!")
    logger().info("opcode 137 sent")
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

    wifi_dut.interfaces.wifi.websocket_close(sock)
    logger().info("websocket_close")
    time.sleep(2)
    assert ws_handler.client_disconnected

    logger().info("Stop Sniffer finally")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")


    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'

    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    websocket_pktcheckpingpong = packet_check_pingpong(wifi_sniffer, logger, decryption_key, dut_mac_address, ["websocket"], capture_filename,
                                 mode=0)

    packet_filter3 = f'(websocket) && (websocket.opcode==9)'
    ping_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert ping_pkt, "Ping packet is not captured in the sniffer"
    packet_filter4 = f'(websocket) && (websocket.opcode==10)'
    pong_pkt = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)
    assert pong_pkt, "Pong packet is not captured in the sniffer"



@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        }
    )
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_web_socket_close_functionality_using_websocketclose_API_C19341(wifi_dut, wifi_access_point, wifi_sniffer, http_server):

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

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80, local_port=5001)

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

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                         'in sniffer'

    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    websocket_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ["http"], capture_filename,
                                 mode=0)

    websocket_pktcheckpingpong = packet_check_pingpong(wifi_sniffer, logger, decryption_key, dut_mac_address,
                                                       ["websocket"], capture_filename,
                                                       mode=0)
    packet_filter3 = f'(websocket) && (websocket.opcode==8)'
    socket_close = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert socket_close, "websocket close packet check is not found in sniffer"



@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        }
    )
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2', "ssid": 'TEST', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_web_socket_opcode8_socketclose_C19342(wifi_dut, wifi_access_point, wifi_sniffer, http_server):

    validation = True
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = 'test_web_socket_opcode8_socketclose_C19342'
    sock = 0

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80, local_port=5001)

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

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                         'in sniffer'
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    websocket_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ["http"], capture_filename,
                                 mode=0)

    websocket_pktcheckpingpong = packet_check_pingpong(wifi_sniffer, logger, decryption_key, dut_mac_address,
                                                       ["websocket"], capture_filename,
                                                       mode=0)
    packet_filter3 = f'(websocket) && (websocket.opcode==8)'
    socket_close = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)
    assert socket_close, "websocket close packet check is not found in sniffer"

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        }
    )
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_rx_over_websocket_disable_finbit_C19344(wifi_dut, wifi_access_point, wifi_sniffer, http_server):

    validation = True
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = 'test_rx_over_websocket_disable_finbit_C19344'
    sock = 0

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(sock, http_server.interfaces.http, server_port=80, local_port=5001)

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

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                         'in sniffer'

    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"


    websocket_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ["http"], capture_filename,
                                   mode=0)

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid| RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "ca_cert": ["ca-chain.cert.pem"],
        }
    )
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd_tls")
def test_max_websocket_over_ssl_C19346(wifi_dut, wifi_access_point, wifi_sniffer, http_server):

    validation = True
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = 'test_max_websocket_over_ssl_C19346'
    #sock = 0

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger().info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)

    logger().info(f"enabling wifi power save mode in DUT......")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info(f"enabling bt power save mode in DUT......")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

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
        wifi_dut.interfaces.wifi.connect_to_websocket_server(2, http_server.interfaces.http, server_port=443, local_port=port)
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


    for sockets in range(2):
        wifi_dut.interfaces.wifi.websocket_close(sockets)
        logger().info("websocket_close")
        time.sleep(2)
        assert ws_handler.client_disconnected

    logger().info("Stop Sniffer finally")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger().info(f"PS-POLL packets are captured in the sniffer")

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == {channel}) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x0028) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find tcp , authentication ,association, eapol packet ' \
                         'in sniffer'
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"

    websocket_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ["http"], capture_filename,
                                 mode=0)
