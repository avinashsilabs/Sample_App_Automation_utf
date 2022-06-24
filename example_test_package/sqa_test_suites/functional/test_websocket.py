import time
import pytest
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from typing import Union
from utf_wiseconnect.devices.rs911x import RS9116CoexMode,RS9116FeatureBitMap, RS9116ConfigFeatureBitMap


def logger():
    return get_logger(__name__)


class WebsocketEventHandler:
    def __init__(self):
        self.client_connected = False
        self.client_disconnected = False
        self.message_received = None

    def on_ws_client_connected(self, client: dict):
        self.client_connected = True

    def on_ws_client_disconnected(self, client: dict):
        self.client_disconnected = True

    def on_ws_message_received(self, client: dict, message: Union[str, bytes]):
        self.message_received = message


# configure ping_count to ping dut
ping_count = 40

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_web_socket_C37479(wifi_dut, wifi_access_point, wifi_sniffer, http_server):

    validation = True
    rejoin_max = 10
    scan_interval = 6
    beacon_missedcount = 40
    first_time_retry = 0
    timeout = 10

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_web_socket_C37479')

    logger().info("Enabling rejoin...")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max, scan_interval=scan_interval,
                                    beacon_missedcount=beacon_missedcount, first_time_retry=first_time_retry,
                                    timeout=timeout)

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(2)

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(0, http_server.interfaces.http)
    time.sleep(0.1)
    assert ws_handler.client_connected
    wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=128, message="Howdy!")
    time.sleep(10)
    assert ws_handler.message_received == "Howdy!"
    wifi_dut.interfaces.wifi.websocket_close()
    time.sleep(0.1)
    assert ws_handler.client_disconnected

    logger().info("Stop Sniffer finally")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    ### TCP PACKET CHECK NEEDS TO ADD ONCE ws_handler.message_received is successful - getting None oin Recieve bytes

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
]
#Verify Tx over web socket with maximum data length
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_Tx_over_web_socket_with_maximum_data_length_C19340(wifi_dut, wifi_access_point, wifi_sniffer, http_server):
    validation = True

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Tx_over_web_socket_with_maximum_data_length_C19340')

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(2)

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(0, http_server.interfaces.http)
    time.sleep(0.1)
    assert ws_handler.client_connected
    data = ""
    for char in range(0, 1451):
        data = data + "a"
    wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=0, message=data)
    time.sleep(10)
    assert ws_handler.message_received == data
    wifi_dut.interfaces.wifi.websocket_close()
    time.sleep(0.1)
    assert ws_handler.client_disconnected

    logger().info("Stop Sniffer finally")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'
    ### TCP PACKET CHECK NEEDS TO ADD ONCE ws_handler.message_received is successful - getting None oin Recieve bytes

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.Bluetooth | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        }
    )
]
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n', "security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.http_server("raspi_lighttpd")
def test_module_sends_ping_request_or_not_when_web_socket_opened_by_giving_opcode_9_C19345(wifi_dut, wifi_access_point, wifi_sniffer, http_server):
    validation = True

    logger().info(" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file='test_Tx_over_web_socket_with_maximum_data_length_C19340')

    logger().info("scan for the ap's.....")
    ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
    ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("connecting to access point.....")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    logger().info("enabling dhcp in DUT.......")
    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(
        result, wifi_dut.interfaces.wifi.IPConfig
    ), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(2)

    logger().info("fetching dut mac address....")
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                     f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) and (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

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
    wifi_dut.interfaces.wifi.connect_to_websocket_server(0, http_server.interfaces.http)
    time.sleep(0.1)
    assert ws_handler.client_connected
    wifi_dut.interfaces.wifi.send_data_over_websocket(0, opcode=9, message="Howdy!")
    time.sleep(10)
    assert ws_handler.message_received == "Howdy!"
    # Yet to verify module sends ping request or not,because we are not receiving tcp packets
    wifi_dut.interfaces.wifi.websocket_close()
    time.sleep(0.1)
    assert ws_handler.client_disconnected

    logger().info("Stop Sniffer finally")
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                         'in sniffer'

    ### TCP PACKET CHECK NEEDS TO ADD ONCE ws_handler.message_received is successful - getting None oin Recieve bytes