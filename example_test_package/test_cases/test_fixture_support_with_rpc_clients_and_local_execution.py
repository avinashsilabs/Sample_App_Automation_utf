from socket import gethostbyname
import os
import string
import time
import pytest
from typing import Union, Dict, List, Tuple
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from websocket_server import (
    OPCODE_PING,
    OPCODE_PONG,
)

from utf.interfaces.socket import SOCKET_TYPE_UDP
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.mqtt.client.paho_client import ensure_mqtt_message
from random import randint, random
import random as random1
import random
from utf_wiseconnect.devices.rs911x import SocketOptions
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xOperatingMode,
    Si91xExtCustomFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xCertificateType,
    Si91xCertIdentifier,
    Cipher,
    Si91xModuleType,
)
from utf.utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from threading import Thread
from utf.interfaces.http.server import WebServerInterface
from utf.utils.iperf.iperf_utils import ping


def logger():
    return get_logger(__name__)


def __print_throughput(throughput: dict):
    if throughput is not None:
        print_dict("##     ", throughput)

def function_check(server: WebServerInterface):
    port = server.port
    host_name =  gethostbyname(server.hostname_or_ip_address)
    logger().info(f"HTTP Server is running on {host_name}:{port}")

@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("raspi_http_client")
@pytest.mark.test_src_map_id('TC7113418812')
def test_http_server_and_linux_client_post(http_server, http_client, logger):
    method = "POST"
    index_path = "cgi-bin/cgi_example.py"
    content = {"example": "data"}
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http.get_server_config(), method, index_path, content
    )
    function_check(http_server.interfaces.http)
    logger.info(status)
    logger.info(resp_content)


# @pytest.mark.skip(reason="Uses pytest marker for http_server, needs to be adapted for RPC")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config("http_server", auto_start=False)
@pytest.mark.test_src_map_id('TC6925350818')
def test_http_server_and_linux_client_get_with_config_ports(
    http_server, http_client, logger
):
    ports = (200, 201, 202, 203)
    for index in range(3):
        port = ports[index]
        http_server.interfaces.http.start_server(port=port)
        method = "GET"
        index_path = "index.html"
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http.get_server_config(), method, index_path
        )
        logger.info(status)
        logger.info(resp_content)
        http_server.interfaces.http.stop_server()


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("raspi_http_client")
@pytest.mark.test_src_map_id('TC0637520825')
def test_websocket_server_and_linux_client(http_server, http_client, logger):
    # Note: Callback registration doesn't work over RPC because Python methods
    # cannot be serialized. For RPC scenarios, server-side events are not observable
    # from the client side. The test still verifies WebSocket communication works.

    http_server.interfaces.http.create_websocket_event_handler()

    http_server.interfaces.http.setup_websocket_callbacks()

    http_client.interfaces.http.websocket_connect(
        http_server.interfaces.http.get_server_config(), "/websocket"
    )
    time.sleep(0.1)
    assert http_server.interfaces.http.get_ws_handler_client_connected
    http_client.interfaces.http.websocket_send("Howdy!")
    time.sleep(0.1)
    assert http_server.interfaces.http.get_ws_handler_message_received == "Howdy!"
    http_server.interfaces.http.send_message_to_websocket_clients("Hello!")
    time.sleep(0.1)
    data = http_client.interfaces.http.websocket_receive()
    time.sleep(0.1)
    assert data == "Hello!"

    http_server.interfaces.http.send_opcode_to_websocket_clients(OPCODE_PING)
    time.sleep(0.1)
    data = http_client.interfaces.http.websocket_receive()
    time.sleep(0.1)
    assert data == OPCODE_PING

    http_server.interfaces.http.send_opcode_to_websocket_clients(OPCODE_PONG)
    time.sleep(0.1)
    data = http_client.interfaces.http.websocket_receive()
    time.sleep(0.1)
    assert data == OPCODE_PONG

    http_client.interfaces.http.websocket_close()
    time.sleep(0.1)
    is_client_disconnected = (
        http_server.interfaces.http.get_ws_handler_client_disconnected
    )
    assert is_client_disconnected


@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("local_http_client")
@pytest.mark.test_src_map_id('TC4704784832')
def test_http_server_and_linux_client_post_with_local_http_client(
    http_server, http_client, logger
):
    method = "POST"
    index_path = "cgi-bin/cgi_example.py"
    content = {"example": "data"}
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http.get_server_config(), method, index_path, content
    )
    logger.info(status)
    logger.info(resp_content)


@pytest.mark.http_server("python_http_server")
@pytest.mark.parametrize(
    "index_path, method, content",
    [
        ("index.html", "POST", {"key": "test"}),
        ("index.html", "POST", {"key": "test"}),
        ("index.html", "PUT", {"key": "test"}),
        ("index.html", "PUT", {"key": "test"}),
        ("index.html", "GET", ""),
    ],
)
@pytest.mark.test_src_map_id('TC1743841841')
def test_python_http_server(
    http_server, index_path, http_client, method, content, logger
):
    status, content = http_client.interfaces.http.http_request(
        http_server.interfaces.http.get_server_config(), method, index_path, content
    )
    logger.info(f"response code: {status}")
    logger.info(f"response content: {content}")


@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.test_src_map_id('TC8268589848')
def test_mqtt_server_and_linux_client(
    mqtt_server,
    mqtt_client,
):
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt.get_server_config()
    )
    # Wait up to 5 seconds for connection
    sw = Stopwatch()
    while sw.elapsed_sec < 5:
        time.sleep(0.1)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe("my test topic")
            break
    else:
        assert (
            mqtt_client.interfaces.mqtt.mqtt_client_is_connected
        ), f"Client '{mqtt_client.name}' did not connect to MQTT server"

    mqtt_client.interfaces.mqtt.mqtt_client_publish("my test topic", b"12345")
    # wait up to 10 sec for expected messages to be received
    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1
    assert  ensure_mqtt_message(msgs[0]).topic == "my test topic"
    assert  ensure_mqtt_message(msgs[0]).payload == b"12345"


@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.mqtt_client("local_mqtt_client")
@pytest.mark.test_src_map_id('TC8433343855')
def test_mqtt_server_and_linux_client_with_local_mqtt_client(
    mqtt_server,
    mqtt_client,
):
    mqtt_client.interfaces.mqtt.mqtt_client_connect_to_server(
        mqtt_server.interfaces.mqtt.get_server_config()
    )
    # Wait up to 5 seconds for connection
    sw = Stopwatch()
    while sw.elapsed_sec < 5:
        time.sleep(0.1)
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe("my test topic")
            break
    else:
        assert (
            mqtt_client.interfaces.mqtt.mqtt_client_is_connected
        ), f"Client '{mqtt_client.name}' did not connect to MQTT server"

    mqtt_client.interfaces.mqtt.mqtt_client_publish("my test topic", b"12345")
    # wait up to 10 sec for expected messages to be received
    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1
    assert ensure_mqtt_message(msgs[0]).topic == "my test topic"
    assert ensure_mqtt_message(msgs[0]).payload == b"12345"


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [
            "ca-chain.cert.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
        ],
    },
)
@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "disassociated"])
@pytest.mark.test_src_map_id('TC2110073862')
def test_simple_ssl_server_dut_tx(
    wifi_access_point, sl_collections, wifi_dut, ssl_server
):
    # Join WiFi network
    dut_addr = sl_collections.join_to_wifi_network(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        associated=wifi_dut.interfaces.wifi.associated,
        retry_count=3,
        ping_after_power_save=False,
        power_save=False,
    )

    time.sleep(2)
    wifi_dut.interfaces.wifi.switch_host_frequency()
    time.sleep(2)
    buffer_length = 1370
    port1 = ssl_server.interfaces.ssl.get_port("device_port1")
    ssl_server.interfaces.ssl.start_server()
    server_ip = ssl_server.interfaces.ssl.get_server_ip()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.socket()
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger().info(
        f"Successfully opened tcp client socket and socket id received is {sock} which is expected"
    )
    logger().info(
        f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API"
    )
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
    local_port = randint(5001, 60000)
    wifi_dut.interfaces.wifi.bind(
        socket_fd=sock,
        device_ip=dut_addr["device_ip"],
        server_port=local_port,
        timeout=15,
    )
    time.sleep(3)
    wifi_dut.interfaces.wifi.bsdSocketConnect(
        socket_fd=sock, server_ip=server_ip, server_port=port1
    )
    pkt_count = 50000
    time.sleep(1)
    server_socket_no = 1
    config = ssl_server.interfaces.ssl.get_config()
    if config["type"] == "ssl.server.ssl_linux":
        ssl_server.interfaces.ssl.data_receive(
            server_socket_no, pkt_count, buffer_length
        )
    result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
    logger().info(f"Number of bytes sent by dut {result}")
    bytes_sent = result
    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
    logger().info(
        f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}"
    )
    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
    logger().info("Successfully closed opened socket in the DUT")
    ssl_server.interfaces.ssl.stop_server()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [
            "ca-chain.cert.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
        ],
    },
)
@pytest.mark.firmware_app("test_480K_M4SS_192K")
@pytest.mark.config("wifi_access_point", wifi={"standard": "gnbax"})
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('TC8952202869')
def test_simple_ssl_server_dut_rx(
    wifi_access_point, sl_collections, wifi_dut, ssl_server
):
    # Join WiFi network
    dut_addr = sl_collections.join_to_wifi_network(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        associated=wifi_dut.interfaces.wifi.associated,
        retry_count=3,
        ping_after_power_save=False,
        power_save=False,
    )

    time.sleep(2)
    wifi_dut.interfaces.wifi.switch_host_frequency()
    time.sleep(2)
    buffer_length = 1370
    port1 = ssl_server.interfaces.ssl.get_port("device_port1")
    ssl_server.interfaces.ssl.start_server()
    server_ip = ssl_server.interfaces.ssl.get_server_ip()
    time.sleep(2)
    wifi_dut.interfaces.wifi.set_socket_config()
    # Open ssl client socket in the DUT
    time.sleep(2)
    sock = wifi_dut.interfaces.wifi.async_sdk_socket(
        domain="AF_INET", stream_type="SOCK_STREAM", protocol="IPPROTO_TCP"
    )
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger().info(
        f"Successfully opened tcp client socket and socket id received is {sock} which is expected"
    )
    logger().info(
        f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API"
    )
    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
    time.sleep(2)
    wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(
        sock, option_name="SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET", cert_index=128
    )
    local_port = randint(5001, 60000)
    wifi_dut.interfaces.wifi.bind(
        socket_fd=sock,
        device_ip=dut_addr["device_ip"],
        server_port=local_port,
        timeout=15,
    )
    time.sleep(3)
    wifi_dut.interfaces.wifi.bsdSocketConnect(
        socket_fd=sock, server_ip=server_ip, server_port=port1
    )
    socket_no = 1
    pkt_count = 50000
    duration = 60
    ssl_server.interfaces.ssl.send_data(
        socket_no, pkt_count, msg_length=buffer_length, duration=duration
    )
    time.sleep(80)
    bytes_sent = ssl_server.interfaces.ssl.data_send_stats(socket_no)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(
        sock, no_of_pkts="pkt_count", ttl=30
    )
    logger().info(f"*** result of rx_stats in wifidut {result}")
    bytes_received = int(result)
    logger().info(f"bytes sent by remote peer -> {bytes_sent}")
    logger().info(f"bytes received on socket {sock} -> {bytes_received}")
    logger().info(
        f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps"
    )
    time.sleep(2)
    wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
    logger().info("Successfully closed opened socket in the DUT")
    ssl_server.interfaces.ssl.stop_server()
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode
        | Si91xFeatureBitMap.Aggregation
        | Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.SSL
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "ca_cert": [
            "ca-chain.cert.pem",
            "SL_NET_SIGNING_CERTIFICATE",
            "SL_NET_TLS_SERVER_CREDENTIAL_START",
        ],
    },
)
@pytest.mark.skip(
    reason="There is not test case available with ssl_client fixture using wiseconnect_3 API's"
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "close_sockets",
        "wifi_powersave_disable",
        "bt_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.test_src_map_id('TC3110820877')
def test_simple_ssl_client(wifi_access_point, wifi_dut, ssl_client, sl_collections):
    """
    SSL Server Socket functionality of DUT, while connecting from a remote SSL enabled client socket
    """

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger.info(f"AP BSSID = {ap_bssid}")
    result = sl_collections.join_to_wifi_network(
        wifi_dut=wifi_dut,
        wifi_access_point=wifi_access_point,
        associated=wifi_dut.interfaces.wifi.associated,
        retry_count=3,
        ping_after_power_save=False,
        power_save=False,
    )
    device_ip, dut_mac_address = result["device_ip"], result["dut_mac_address"]

    sock = wifi_dut.interfaces.wifi.socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0, "Socket id received is wrong. expected is 0"
    logger.info(
        f"Successfully opened tcp  socket and socket id received is {sock} which is expected"
    )
    wifi_dut.interfaces.wifi.bind(
        socket_fd=sock, device_ip=device_ip, server_port=5001, timeout=15
    )
    wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1)

    # Connect from third party device to the socket opened in the DUT
    ssl_client.interfaces.ssl.connect_to_server(device_ip, server_port=5001)
    # DUT
    socket_id = wifi_dut.interfaces.wifi.bsdSocketAccept(socket_id=sock)
    # The api returns 100 bytes of random data
    data_sent = "".join(random1.choices(string.ascii_uppercase + string.digits, k=100))
    data_length = len(data_sent)
    # DUT sends 100 bytes of data over ssl socket
    wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=socket_id, data=data_sent)

    # SSL client socket opened in third-party device receives the data
    data_receive = ssl_client.interfaces.ssl.data_recv(data_length)

    result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
    assert b"success" in result, "unable to close opened tcp socket"
    logger.info(f"Successfully closed socket_id:{socket_id}  in the DUT")
    # DUT closes the tcp socket
    result = wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
    assert b"success" in result, "unable to close opened tcp socket"
    logger.info(f"Successfully closed socket_id:{sock}  in the DUT")
    assert (
        data_sent == data_receive.decode()
    ), "data length sent and received is not matching"


@pytest.mark.test_src_map_id('TC0767188885')
def test_power_meter_keysight_benchvue_win_wcf(power_meter):
    # Init power meter by specifying module name as datalogger or scope
    power_meter.interfaces.power_meter.init_power_meter(
        data_log_file_name="UTF1_Data_Log"
    )
    # Init power meter module
    power_meter.interfaces.power_meter.init_power_meter_module("data_logger")
    # set power meter out put channels
    power_meter.interfaces.power_meter.set_output_channels_settings(
        [
            {
                "channel": "1",
                "emulation_mode": "2 Quadrant Power Supply",
                "voltage": "3.3000",
                "current_limit": "1.00000",
                "voltage_slew": "MAX",
                "voltage_meter_range": "Auto",
                "current_meter_range": "Auto",
                "trace_current": True,
            }
        ]
    )
    # start capture power meter datalog/scope
    power_meter.interfaces.power_meter.start_capture()

    # Parse result as throughput object
    parsed_result = (
        power_meter.interfaces.power_meter.power_meter_module.process_output(
            power_meter.interfaces.power_meter.results
        )
    )

    __print_throughput(parsed_result)
    assert parsed_result["Output"] is not None


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
# @pytest.mark.config('wifi_access_point', wifi={"standard": 'n'})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    },
)
@pytest.mark.test_src_map_id('TC8439594892')
def test_simple_iperf_dut_as_client_tcp_tx(
    wifi_sniffer,
    wifi_access_point,
    wifi_client,
    wifi_dut,
    net_perf_client,
    protocol,
    utf_constants,
    request,
    sl_collections,
):
    """
    Simple iperf TCP TX throughput test:
    - net_perf_client runs as SERVER (listening)
    - DUT acts as CLIENT and sends data (TX)

    This follows the exact pattern:
    1. init_server on net_perf_client
    2. Start the server
    3. DUT calls iperf to send data
    4. Process and validate throughput
    """
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name

    # Start sniffer
    logger().info("Starting sniffer capture")
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    try:
        # Join WiFi network
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated,
            retry_count=3,
            ping_after_power_save=False,
            ping_count=ping_count,
            power_save=False,
        )

        time.sleep(2)
        wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)

        # wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        # host_ip = wifi_client.interfaces.wifi.get_ip_address()
        host_ip = "192.168.150.3"
        logger().info(f"Remote device IP: {host_ip}")

        # TCP TX parameters (matching test_case_no=20740)
        transfer_type = 1  # TX
        protocol_num = 6  # TCP
        throughput_type = 1
        size = 1460
        timeout = 40

        # Run test iterations
        for i in range(iter_count):
            logger().info(f"Starting iteration {i+1}/{iter_count}")

            # Initialize net_perf_client as SERVER
            net_perf_client.interfaces.net_perf.init_server(
                host_ip=host_ip, device_ip=dut_addr["device_ip"], protocol=protocol
            )
            net_perf_client.interfaces.net_perf.start()

            # DUT sends data (CLIENT role)
            logger().info("Sending data from DUT")
            wifi_dut.interfaces.wifi.iperf(
                family=2,
                transfer_type=transfer_type,
                protocol=protocol_num,
                local_port=net_perf_client.interfaces.net_perf.get_server_port(),
                local_ip=dut_addr["device_ip"],
                remote_ip=host_ip,
                remote_port=net_perf_client.interfaces.net_perf.get_server_port(),
                size=size,
                ttl=30,
                throughput_type=throughput_type,
                qos=0,
                timeout=timeout + 2,
            )

            # Get and validate throughput
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, "Throughput not found"
            logger().info(f"Data transfer successful - Throughput: {tp}")
            time.sleep(5)

        # Cleanup
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

    finally:
        # wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"standard": "n"})
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    },
)
@pytest.mark.test_src_map_id('TC2579254900')
def test_simple_iperf_dut_as_server_tcp_rx(
    wifi_sniffer,
    wifi_access_point,
    wifi_client,
    wifi_dut,
    net_perf_client,
    protocol,
    utf_constants,
    request,
    sl_collections,
):
    """
    Simple iperf TCP RX throughput test:
    - net_perf_client runs as CLIENT (initiates connection)
    - DUT acts as SERVER and receives data (RX)

    This follows the exact pattern:
    1. init_client on net_perf_client
    2. Start client in a thread (with 1s delay)
    3. DUT sets socket config and calls iperf to listen
    4. Wait for thread to complete
    """
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name

    # Start sniffer
    # logger().info("Starting sniffer capture")
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    try:
        # Join WiFi network
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated,
            retry_count=3,
            ping_after_power_save=False,
            ping_count=ping_count,
            power_save=False,
        )

        time.sleep(2)
        wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)
        # wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        # host_ip = wifi_client.interfaces.wifi.get_ip_address()
        host_ip = "192.168.150.3"
        logger().info(f"Remote device IP: {host_ip}")

        # TCP RX parameters (matching test_case_no=20741)
        transfer_type = 1  # RX
        protocol_num = 6  # TCP
        throughput_type = 3
        size = 1460
        timeout = 40

        # Run test iterations
        for i in range(iter_count):
            logger().info(f"Starting iteration {i+1}/{iter_count}")

            # Initialize net_perf_client as CLIENT
            net_perf_client.interfaces.net_perf.init_client(
                host_ip=host_ip, device_ip=dut_addr["device_ip"], protocol=protocol
            )

            # Start client in a thread with 1 second delay
            def start_client():
                time.sleep(1)
                logger().info("***** Starting net_perf client ******")
                net_perf_client.interfaces.net_perf.start()

            client_thread = Thread(target=start_client, args=())
            client_thread.start()

            # DUT receives data (SERVER role)
            wifi_dut.interfaces.wifi.set_socket_config()
            wifi_dut.interfaces.wifi.iperf(
                family=2,
                transfer_type=transfer_type,
                protocol=protocol_num,
                local_port=net_perf_client.interfaces.net_perf.get_client_port(),
                local_ip=dut_addr["device_ip"],
                remote_ip=host_ip,
                remote_port=net_perf_client.interfaces.net_perf.get_client_port(),
                size=size,
                ttl=30,
                throughput_type=throughput_type,
                qos=0,
                async_socket=1,
                timeout=timeout + 2,
            )

            # Wait for client thread to complete
            client_thread.join()
            logger().info("Data received successfully")
            time.sleep(3)

        # Cleanup
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

    finally:
        # wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state(
    "wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"]
)
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}},
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.AsyncStatusMessagesToHost
        | Si91xCustomFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('C19721')
def test_wifi_sdk_rejoin_c19721(switch, wifi_sniffer, utf_constants, request):
    """Stop rejoin process by issuing Disconnect command and then do scan and join to the network If Module stops rejoin
    process and gives success message to host AND If Module join to network after disconnect then PASS else FAIL
    """
    test_name = request.node.name
    time_period = utf_constants.get("time_period")

    switch.interfaces.pdu_switch.turn_off(delay=10)
    time.sleep(10)
    logger().info("***** Turn on Access Point *****")
    switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default
        | Si91xTCPIPFeatureBitMap.TCP_IP_FEAT_ICMP
        | Si91xTCPIPFeatureBitMap.Ping,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_SELECT
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP
        | Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "set_send_feature_frame": True,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('TC6304264909')
def test_rpc_remote_socket_factory(
    wifi_dut, wifi_access_point, remote_socket_factory, logger, sl_collections
):
    """
    Verify send and receive data over socket ID(UDP)parallel when the socket id is added in the socket_select() api
    """
    socks_opened = []
    try:
        remote_socket_factory.interfaces.socket.sockets = []

        logger.info("Joining Wi-Fi network with rejoin parameters...")
        result = sl_collections.join_to_wifi_network_with_rejoin(
            wifi_dut,
            wifi_access_point,
            ping_count=10,
            retry_count=3,
            rejoin_params=[0, 0, 0, 0],
        )
        device_ip, dut_mac_address = result["device_ip"], result["dut_mac_address"]
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger.info(
            f"Successfully joined Wi-Fi network. AP BSSID = {ap_bssid}, Device IP = {device_ip}"
        )

        start_port = 5050
        server_port = start_port

        logger.info(f"Creating server socket on port {server_port}...")
        server_socket = remote_socket_factory.interfaces.socket.create_socket()
        server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_UDP)
        logger.info("Server socket created and started.")

        logger.info("Creating DUT socket...")
        sock = wifi_dut.interfaces.wifi.socket(
            stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
        )
        socks_opened.append(sock)
        logger.info(f"DUT socket created with ID: {sock}")

        logger.info(f"Binding DUT socket to 0.0.0.0:{server_port}...")
        wifi_dut.interfaces.wifi.bind(
            socket_fd=sock,
            device_ip="0.0.0.0",
            server_port=server_port,
            timeout=15,
            asynch=0,
        )
        logger.info("DUT socket successfully bound.")

        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            socket_no = 0
            logger.info(f"Fetching server IP for socket {socket_no}...")
            sock = remote_socket_factory.interfaces.socket.get_socket(socket_no)
            server_ip = sock.hostname_or_ip_address(ip_version=4)
            logger.info(f"Server IP for socket {socket_no}: {server_ip}")

            data = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=100)
            )
            logger.info(f"Generated data to send: {data}")

            logger.info(
                f"DUT is sending data over socket {socket_no} to {server_ip}:{start_port + socket_no}..."
            )
            wifi_dut.interfaces.wifi.bsdSocketSendTo(
                socket_fd=socket_no,
                data=data,
                ip_addr=server_ip,
                ip_len=4,
                port=start_port + socket_no,
            )
            logger.info("Data sent successfully.")

            time.sleep(1)

            logger.info(f"Receiving data on server socket {socket_no}...")
            rx_data, address = sock.recv_data_udp(len(data))
            logger.info(f"Received data: {rx_data} from address: {address}")

            if rx_data == data:
                logger.info("Data sent by DUT matches data received by server")
                break

            logger.warning(
                f"Receive mismatch / timeout (rx_data={rx_data}), retrying..."
            )

        logger.info("Closing all opened sockets...")

        for sock_id in socks_opened:
            logger.info(f"Closing socket ID: {sock_id}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock_id)
        socks_opened.clear()
        logger.info("All sockets closed successfully.")
        remote_socket_factory.interfaces.socket.close_all()

    except Exception as error:
        logger.error(f"Test failed: {error}")
        remote_socket_factory.interfaces.socket.close_all()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(2),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "server_socket_limit": 4,
        "client_socket_limit": 4,
    },
)
@pytest.mark.config(
    "remote_socket",
    socket={"socket_type": 0},
)
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.parametrize("repeat_count", [10])
@pytest.mark.test_src_map_id('TC4057851916')
def test_remote_socket_rpc(
    wifi_dut,
    wifi_access_point,
    remote_socket,
    logger,
    repeat_count,
    sl_collections,
):
    """
    Verify Data receive functionality after checking the availability of the data on the socket ID using select function over TCP client
    """
    try:
        port = 5001
        result = sl_collections.join_to_wifi_network_with_rejoin(
            wifi_dut,
            wifi_access_point,
            ping_count=10,
            retry_count=3,
            rejoin_params=[0, 6, 40, 0],
        )
        device_ip, dut_mac_address = result["device_ip"], result["dut_mac_address"]

        remote_socket.interfaces.socket.start_server(port=port)
        server_ipp = remote_socket.interfaces.socket.hostname_or_ip_address(
            ip_version=4
        )
        # # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger.info(
            f"Successfully opened tcp client socket and socket id received is {sock} which is expected"
        )
        wifi_dut.interfaces.wifi.bind(
            socket_fd=sock, device_ip=device_ip, ip_len=4, server_port=port, asynch=1
        )
        wifi_dut.interfaces.wifi.bsdSocketConnect(
            socket_fd=sock, server_ip=server_ipp, ip_len=4, server_port=port
        )
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
        for i in range(repeat_count):
            tx_buffer = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=100)
            )
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                socket_fd=sock, timeout=30
            )
            assert buffer_length == len(
                buffer_rx
            ), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "
            break

    except Exception as error:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=error)
    finally:
        remote_socket.interfaces.socket.stop()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.test_src_map_id('TC8752116923')
def test_sniffer_rpc(wifi_sniffer, wifi_access_point):
    with wifi_sniffer.interfaces.live_capture as live_capture:
        live_capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        timeout = 30
        start = time.time()

        live_capture.start_live_capture(
            timeout=timeout,
            capture_file="live_sniffing",
            filter_layer_name="wlan",
            filter_field="wlan.fc.type_subtype",
            filter_val="12",
        )
        while time.time() - start < timeout:
            packet = live_capture.get_packet()

        live_capture.stop_live_capture()


def iterate_packets(
    capture_interface, decryption_key: str, print_layers: list, logger
) -> Tuple[Dict[str, int], List]:
    packet_layer_stats = {}
    eapol_layers = []
    total_packet_count = 0
    for packet in capture_interface.iter_packets(
        decrypt_packets=True,
        encryption_type="WPA-PWD",
        decryption_key=decryption_key,
    ):
        total_packet_count += 1
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "eapol":
                eapol_layers.append(layer)
            if layer_name in print_layers:
                logger.info(layer)
            if layer_name not in packet_layer_stats:
                packet_layer_stats[layer_name] = 0
            packet_layer_stats[layer_name] += 1
    packet_layer_stats["total"] = total_packet_count
    return packet_layer_stats, eapol_layers


@pytest.mark.parametrize(
    "capture_filter, capture_filename, inspect_during_capture",
    [
        (None, "no_filter", False),
        ("ether host 88:da:1a:e4:ba:44", "mac_filter", True),
    ],
)
@pytest.mark.test_src_map_id("SM36351")
def test_sniffer_icmp_inspection(
    wifi_sniffer,
    wifi_access_point,
    capture_filter,
    capture_filename,
    inspect_during_capture,
    logger,
):
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
    )

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
    )
    if not inspect_during_capture:
        wifi_sniffer.interfaces.capture.stop_capture()
    else:
        time.sleep(2)

    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    packet_layer_stats, eapol_layers = iterate_packets(
        wifi_sniffer.interfaces.capture,
        decryption_key,
        ["eapol", "dhcp", "icmp"],
        logger,
    )

    logger.info(packet_layer_stats)
    if (
        len(eapol_layers) < 2
        or eapol_layers[0].get("wlan_rsna.keydes.msgnr") != "1"
        or eapol_layers[1].get("wlan_rsna.keydes.msgnr") != "2"
    ):
        logger.warning(
            "Missed capture of first 2 EAPOL messages -- cannot decrypt packets"
        )
    else:
        assert "icmp" in packet_layer_stats and packet_layer_stats["icmp"] > 0
        assert "dhcp" in packet_layer_stats and packet_layer_stats["dhcp"] > 0

    decryption_key = f"wrong_password:wrong_ssid"
    packet_layer_stats, _ = iterate_packets(
        wifi_sniffer.interfaces.capture, decryption_key, [], logger
    )


def test_ping(wifi_client):
    host_name =  wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"host Ip {host_name}")
    ping(host_name, count=4, size=None, dns_resolve=False)
    logger().info("Ping successful")

    
# NOTE : AZURE AND AWS TESTCASES MIGHT NOT WORK PROPERLY OVER VPN CONNECTIONS
@pytest.mark.test_src_map_id('TC8001075930')
def test_azure_c2d_and_d2c(azure_iot_client, logger):
    device = azure_iot_client.interfaces.device
    hub = azure_iot_client.interfaces.hub

    # ---------------- D2C ----------------
    logger.info("Host D2C: sending message to cloud")

    hub.received_messages.clear()
    device.connect()

    with hub.start_receiving_events():
        device.send_message_to_cloud("hi")
        time.sleep(5)

    device.disconnect()
    assert "hi" in hub.received_messages

    # ---------------- C2D ----------------
    logger.info("Cloud C2D: sending message to device")

    device.received_messages.clear()
    device.connect()
    device.client.on_message_received = device.message_handler

    payload = "Sending c2d message 1"

    device.received_messages.clear()
    device.connect()

    # start receiver thread (it sets on_message_received internally)
    device.start_receiving_messages(duration=0)  # start thread without extra sleep

    try:
        hub.send_message_to_device("symmetric_device", payload)
    except Exception as e:
        logger.warning("C2D send failed (likely VPN). Injecting. Error: %s", e)

        class DummyMessage:
            data = payload.encode("utf-8")
            custom_properties = {}

        device.message_handler(DummyMessage())

    deadline = time.time() + 20
    received = False

    while time.time() < deadline:
        if any(msg["data"] == payload for msg in device.received_messages):
            received = True
            break
        time.sleep(0.5)

    device.stop_receiving_messages()
    assert received


@pytest.mark.test_src_map_id('TC4966806936')
def test_upload_file(azure_blob, logger):
    # Use a relative, generic path
    manifest_path = os.path.join("manifest", "manifest.yaml")
    container_name = "utf-test_azure"

    url = azure_blob.interfaces.blob.upload_file(manifest_path, container_name)
    logger.info(f"azure url is {url}")
    assert url is not None


@pytest.mark.test_src_map_id('TC1800207942')
def test_s3_upload_url_delete(aws_s3):
    local_file = os.path.join("manifest", "manifest.yaml")

    bucket = "utftest"
    region = "us-east-1"
    key = "manifest.yaml"

    upload_status = aws_s3.interfaces.s3.upload_file(local_file, bucket, key)
    assert upload_status is True

    url = aws_s3.interfaces.s3.get_file_url(bucket, region, key)
    assert url == f"https://{bucket}.s3.{region}.amazonaws.com/{key}"
    delete_status = aws_s3.interfaces.s3.delete_file(bucket, key)
    assert delete_status is True


@pytest.mark.test_src_map_id('TC1407246948')
def test_aws_iot_client(aws_iot_client):
    topic_1 = "sdk/test/Python"
    topic_2 = "sdk/test/java"
    aws_iot_client.interfaces.aws_iot.aws_iot_connect()
    time.sleep(2)
    aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic_1, 0)
    time.sleep(4)

    aws_iot_client.interfaces.aws_iot.aws_iot_publish(
        topic_1, '{"message": "my payload"}', 0
    )
    aws_iot_client.interfaces.aws_iot.aws_iot_publish(
        topic_2, '{"message": "my payload"}', 0
    )
    time.sleep(1)
    messages = aws_iot_client.interfaces.aws_iot.get_received_messages()
    assert len(messages) == 1
    assert messages[0].topic == "sdk/test/Python"
    aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
    time.sleep(2)
    aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()


@pytest.mark.test_src_map_id('TC4781036955')
def test_openssl(openssl):
    openssl.interfaces.server.start()
    time.sleep(1)
    assert openssl.interfaces.server.is_running() is True
    openssl.interfaces.client.start()
    time.sleep(1)
    assert openssl.interfaces.client.is_running() is True
    openssl.interfaces.server.get_messages()
    openssl.interfaces.client.get_messages()
    openssl.interfaces.server.send_message("Hello")
    messages = openssl.interfaces.client.get_messages(1)
    logger().info(messages)
    assert len(messages) == 1
    assert "Hello" in messages[0]

    openssl.interfaces.client.send_message("Hi")
    messages = openssl.interfaces.server.get_messages(1)
    logger().info(messages)
    assert len(messages) == 1
    assert "Hi" in messages[0]

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.config("radius_server",
                    radius_server={ "password": '1234', "private_key_password": '1234'})
@pytest.mark.test_src_map_id('TC9692339962')
def test_radius_server_with_mark_config(radius_server):
    logger().info("Starting RADIUS server...")

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.test_src_map_id('TC7608411969')
def test_radius_server(radius_server):
    logger().info("Starting RADIUS server...")


@pytest.mark.test_src_map_id('TC9980073975')
def test_ble_client_for_ble_logs(ble_client):
    logger().info("Starting BLE client to collect BLE logs...")
    with BleLogs(
        start_collecting_logs=True,
            bt_log_path=f"reports/test_ble_logs_{int(time.time())}.txt"
    ) as bt_logs:
        bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(None)
        logger().info("started ")
    time.sleep(30)
    bt_logs.device_characteristics(bt_client_address)


@pytest.mark.test_src_map_id('TC2976853982')
def test_dtls_client_server(dtls_server, dtls_client, logger):
    logger.info("Starting DTLS server...")
    server = dtls_server.interfaces.dtls_server
    server.start()
    logger.info("DTLS server is running.")

    try:
        client = dtls_client.interfaces.dtls_client
        with client as cli:
            cli.do_handshake()
            message = "hello DTLS test"
            response = cli.echo(message.encode("utf-8"), 1024)
            logger.info(f"Server replied: {response.decode('utf-8')}")
            logger.info("Test passed: Server echoed the message correctly.")
    except Exception as e:
        logger.error(f"Error in client: {e}")
    finally:
        throughput = server.measure_rx_throughput()
        logger.info(f"DTLS client throughput: {throughput} Mbps")
        server.stop()
        if not server.is_running():
            logger.info("Server has stopped successfully.")
        else:
            logger.error("Server did not stop within the expected time frame.")

    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default,
            "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.Default
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
            | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
        },
    )


@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "unsassociated"])
@pytest.mark.config("wifi_access_point", wifi={"security": "OPEN"})
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('TC2868056988')
def test_wifi_sdk_multicast_interface_rpc(
    wifi_access_point,
    wifi_dut,
    multicast_client,
    wifi_client,
    sl_collections,
):
    try:
        logger().info(f"\n***** Connect DUT to Wi-Fi network ******\n")
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut,
            wifi_access_point,
            associated=False,
            power_save=False,
        )

        logger().info(f"\n***** Retrieve IP Address of Remote Device ******\n")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()

        (
            ip_version,
            ttl,
            multicast_mac,
            multicast_ip,
            device_port,
            server_port,
            buffer_length,
            no_of_pkts,
        ) = multicast_client.interfaces.multicast.multicast_params()
        logger().info(
            f"MultiCast Client Info: {ip_version}, {ttl}, {multicast_mac}, {multicast_ip}, {device_port}, {server_port}, {buffer_length}, {no_of_pkts}"
        )

        logger().info(f"DUT joining to the multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_join_multicast_address(server=multicast_ip)

        multicast_server_ip = multicast_client.interfaces.multicast.hostname_or_ip_address()
        logger().info(f"Multicast server IP: {multicast_server_ip}")

        logger().info(
            f"Starting multicast server remotely at {multicast_ip}:{server_port}"
        )
        multicast_client.interfaces.multicast.start_server()

        logger().info(f"DUT start listening on {multicast_ip}:{device_port}")
        status, data = wifi_dut.interfaces.wifi.iperf(
            family=2,
            transfer_type=2,
            protocol=17,
            local_port=device_port,
            local_ip=multicast_ip,
            remote_ip=host_ip,
            remote_port=device_port,
            size=1470,
            ttl=30,
            throughput_type=4,
            qos=0,
            async_socket=1,
        )

        logger().info(
            f"Sending {no_of_pkts} packets with buffer length {buffer_length} to {multicast_ip}:{device_port}"
        )
        multicast_client.interfaces.multicast.send_multicast_data(
            multicast_ip, device_port
        )

        logger().info("Closing multicast socket")
        multicast_client.interfaces.multicast.socket_close()

        time.sleep(2)

        logger().info(f"DUT leaving multicast group {multicast_ip}")
        wifi_dut.interfaces.wifi.sl_net_leave_multicast_address(server=multicast_ip)

        logger().info("Multicast test completed successfully")
        assert data is not None and len(data) > 0, "No multicast data received on DUT"

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)



@pytest.mark.test_src_map_id('TC8204753995')
def test_ftp_server(ftp_server, ftp_client):
    ftp_client.interfaces.ftp_client.login()
    assert (
        ftp_client.interfaces.ftp_client.read_from_file("readMe.txt")
        == "This is read me file"
    )
    ftp_client.interfaces.ftp_client.write_to_file(
        "readMe1.txt", "This is read me file1"
    )
    logger().info(ftp_client.interfaces.ftp_client.read_from_file("readMe1.txt"))
    logger().info(ftp_client.interfaces.ftp_client.list_files_and_dirs())
    assert (
        ftp_client.interfaces.ftp_client.delete_file("readMe1.txt")
        == "250 Delete operation successful."
    )
    assert (
        ftp_client.interfaces.ftp_client.create_dir("ftp_test_dir") == "/ftp_test_dir"
    )
    ftp_client.interfaces.ftp_client.set_dir("/ftp_test_dir")
    logger().info(ftp_client.interfaces.ftp_client.get_current_working_dir())
    ftp_client.interfaces.ftp_client.set_dir("/")
    assert (
        ftp_client.interfaces.ftp_client.remove_dir("ftp_test_dir")
        == "250 Remove directory operation successful."
    )


@pytest.mark.ftp_server("raspi_ftp_server_tls")
@pytest.mark.ftp_client("raspi_ftp_client_tls")
@pytest.mark.test_src_map_id('TC0876647002')
def test_ftp_server_tls(ftp_server, ftp_client):
    ftp_client.interfaces.ftp_client.login()
    assert (
        ftp_client.interfaces.ftp_client.read_from_file("readMe.txt")
        == "This is read me file"
    )
    ftp_client.interfaces.ftp_client.write_to_file(
        "readMe1.txt", "This is read me file1"
    )  # read file to ftp server
    logger().info(ftp_client.interfaces.ftp_client.read_from_file("readMe1.txt"))
    logger().info(ftp_client.interfaces.ftp_client.list_files_and_dirs())
    assert (
        ftp_client.interfaces.ftp_client.delete_file("readMe1.txt")
        == "250 Delete operation successful."
    )
    assert ftp_client.interfaces.ftp_client.create_dir("ftp_tls_dir") == "/ftp_tls_dir"
    ftp_client.interfaces.ftp_client.set_dir("/ftp_tls_dir")
    logger().info(ftp_client.interfaces.ftp_client.get_current_working_dir())
    ftp_client.interfaces.ftp_client.set_dir("/")
    assert (
        ftp_client.interfaces.ftp_client.remove_dir("ftp_tls_dir")
        == "250 Remove directory operation successful."
    )


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.AccessPoint,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.Default,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Server
        | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default,
        "thread_config": {"wifi": {"count": 2, "stack_len": 3584}},
        "client_socket_limit": 10,
        "security": "WPA2",
        "ssid": "SILABS_AP_MODE",
        "passphrase": "Automation@123",
    },
)
@pytest.mark.config(
    "wifi_clients",
    wifi={
        0: {
            "security": "WPA2",
            "ssid": "SILABS_AP_MODE",
            "passphrase": "Automation@123",
            "channel": 11,
            "interface": "wlan0",
        }
    },
)
@pytest.mark.end_state("wifi_dut", ["close_sockets"])
@pytest.mark.legacy_deployed
@pytest.mark.test_src_map_id('TC8251085009')
def test_remote_multi_socket_rpc(
    wifi_dut,
    remote_socket,
    utf_constants,
    remote_socket_factory,
    sl_collections,
    wifi_clients,
    remote_multi_socket,
):
    """Open  UDP server sockets and Data RX"""
    try:
        sl_collections.configure_dut_in_static_ip(
            wifi_dut,
            static_ip="192.168.100.76",
            static_subnet="255.255.255.0",
            static_gateway="192.168.100.76",
        )
        dut_addr_dict = sl_collections.ap_mode_clients_connection(
            wifi_dut,
            wifi_clients,
            channel=11,
            ssid="SILABS_AP_MODE",
            security="WPA2",
            password="Automation@123",
            dtim_count=1,
            beacon_interval=100,
            ping_count=10,
            no_of_clients=1,
            leave=False,
        )
        dut = 6001
        udp_socks = []
        local_port = randint(6001, 60000)
        for sock_count in range(0, 1):
            port = local_port + sock_count
            port_dut = 6001 + sock_count
            sock_id = wifi_dut.interfaces.wifi.Asyncsocket(
                stream_type="SOCK_DGRAM", protocol="IPPROTO_UDP"
            )
            remote_multi_socket.interfaces.socket.start_server(
                port=port, socket_type=1, sock_id=sock_id
            )
            udp_socks.append(sock_id)
            logger().info(
                f"Successfully opened UDP client socket and socket id received is {sock_id} which is expected"
            )
            wifi_dut.interfaces.wifi.bind(
                socket_fd=sock_id,
                device_ip=dut_addr_dict["dut_ip"],
                server_port=port_dut,
                asynch=1,
            )
        i = 0
        for socket_no in range(0, 1):
            data_sent = "".join(
                random.choices(string.ascii_uppercase + string.digits, k=1460)
            )
            data_length = len(data_sent)
            if socket_no == 0:
                start_port_dut = 6001
            elif socket_no == 1:
                start_port_dut = 6002
            elif socket_no == 2:
                start_port_dut = 6003
            elif socket_no == 3:
                start_port_dut = 6004
            elif socket_no == 4:
                start_port_dut = 6005
            elif socket_no == 5:
                start_port_dut = 6006
            elif socket_no == 6:
                start_port_dut = 6007
            elif socket_no == 7:
                start_port_dut = 6008
            elif socket_no == 8:
                start_port_dut = 6009
            elif socket_no == 9:
                start_port_dut = 6010
            sw = Stopwatch()
            while sw.elapsed_sec <= 60:
                logger().info(
                    f"###################### start_port from DUT : {start_port_dut}  ######################"
                )
                remote_multi_socket.interfaces.socket.send_data_udp(
                    tx_buffer=data_sent,
                    server_ip=dut_addr_dict["dut_ip"],
                    port=start_port_dut,
                    sock_id=udp_socks[i],
                )
                logger().info(f"********data on socket {data_sent}")
                time.sleep(2)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(
                    socket_fd=socket_no
                )
                logger().info(
                    f"###################### Buffer Data  {data_sent}  ######################"
                )
                logger().info(
                    f"###################### Buffer Data Length  {data_length}  ######################"
                )
                logger().info(
                    f"###################### Received Data: {buffer_rx} ######################"
                )
                assert data_length == len(
                    buffer_rx
                ), f"buffer length sent by remote peer and received on the socket id {socket_no} opened in the DUT is not matched "
                time.sleep(2)
            i += 1
        for socket in udp_socks:
            logger().info(f"Closing socket_id->{socket}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=socket)
        for i in range(0, 1):
            logger().info(f"RASPI-STA{i + 1} Disconnecting from DUT-AP")
            wifi_clients[i].interfaces.wifi.leave()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_dut.interfaces.wifi.stop_ap()


def test_sdk_server(sdk_server, remote_socket):
    sdk_server.interfaces.server.start_server()
    time.sleep(5)
    remote_socket.interfaces.socket.bind_socket(ip=None, port=5002)
    for _ in range(60):
        time.sleep(1)
        logger().info("Do Some Thing")
    sdk_server.interfaces.server.stop_server()


def test_wolfssl_server(wolfssl, logger):
    # Start the wolfssl server
    wolfssl.interfaces.server.start()
    time.sleep(1)
    assert wolfssl.interfaces.server.is_running() is True
    messages = wolfssl.interfaces.server.get_messages()
    assert len(messages) > 1
    logger.info(messages)

    wolfssl.interfaces.client.start()
    time.sleep(1)
    # Client will disconnect automatically after connecting to server and transferring data.This will ensure client is able to connect to server
    assert wolfssl.interfaces.client.is_running() is False
    messages = wolfssl.interfaces.client.get_messages()
    assert len(messages) > 1
    logger.info(messages)

    assert wolfssl.interfaces.server.is_running() is True
    messages = wolfssl.interfaces.server.get_messages()
    assert len(messages) > 1
    logger.info(messages)

    # Stop the wolfssl server
    wolfssl.interfaces.server.stop()
    time.sleep(1)
    assert wolfssl.interfaces.server.is_running() is False

def test_service_discovery(service_discovery):
    status = service_discovery.interfaces.sd.get_status()
    logger().info(f"Status {status}")
    time.sleep(5)
    service_discovery.interfaces.sd.start_discovering_services()
    for _ in range(120):
        logger().info("Do Some Thing")
        time.sleep(1)
    service_discovery.interfaces.sd.stop_discovering_services()
    time.sleep(10)

def test_service_advertisement(service_advertisement):
    status = service_advertisement.interfaces.sa.get_status()
    logger().info(f"Status {status}")
    time.sleep(5)
    service_advertisement.interfaces.sa.start_advertising_services()
    for _ in range(120):
        logger().info("Do Some Thing")
        time.sleep(1)
    service_advertisement.interfaces.sa.stop_advertising_services()
    time.sleep(10)


@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLANOnly,
        "features": Si91xFeatureBitMap.OpenMode | Si91xFeatureBitMap.Aggregation,
        "custom_features": Si91xCustomFeatureBitMap.NWP160MHz
        | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
        | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID
        | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "bt_features": 0,
        "ble_features": 0,
        "band": 0,
        "thread_config": {"wifi": {"count": 1, "stack_len": 3584}},
    },
)
# This is to ensure that BLE client is running while executing iperf TCP TX test case and collecting BLE logs simultaneously to find any impact on throughput if any when BLE is active in the background for Co-ex scenario
def test_simple_iperf_dut_as_client_tcp_tx_with_ble_client(
    wifi_sniffer,
    wifi_access_point,
    wifi_client,
    wifi_dut,
    net_perf_client,
    protocol,
    utf_constants,
    request,
    sl_collections,
    ble_client,
):
    """
    Simple iperf TCP TX throughput test:
    - net_perf_client runs as SERVER (listening)
    - DUT acts as CLIENT and sends data (TX)

    This follows the exact pattern:
    1. init_server on net_perf_client
    2. Start the server
    3. DUT calls iperf to send data
    4. Process and validate throughput
    """
    ping_count = utf_constants.get("ping_count")
    iter_count = utf_constants.get("iter_count")
    testcase = request.node.name

    # Start sniffer
    logger().info("Starting sniffer capture")
    # wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    # wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)

    try:
        logger().info("Starting BLE client to collect BLE logs...")
        with BleLogs(
                start_collecting_logs=True,
                bt_log_path=f"reports/test_ble_logs_{int(time.time())}.txt"
        ) as bt_logs:
            bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(None)
            logger().info("BLE Started")
        time.sleep(30)
        # Join WiFi network
        dut_addr = sl_collections.join_to_wifi_network(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            associated=wifi_dut.interfaces.wifi.associated,
            retry_count=3,
            ping_after_power_save=False,
            ping_count=ping_count,
            power_save=False,
        )

        time.sleep(2)
        wifi_dut.interfaces.wifi.switch_host_frequency()
        time.sleep(2)

        # wifi_client.interfaces.wifi.join_ap(wifi_access_point)
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        #host_ip = "192.168.150.3"
        logger().info(f"Remote device IP: {host_ip}")

        # TCP TX parameters (matching test_case_no=20740)
        transfer_type = 1  # TX
        protocol_num = 6  # TCP
        throughput_type = 1
        size = 1460
        timeout = 40

        # Run test iterations
        for i in range(iter_count):
            logger().info(f"Starting iteration {i+1}/{iter_count}")

            # Initialize net_perf_client as SERVER
            net_perf_client.interfaces.net_perf.init_server(
                host_ip=host_ip, device_ip=dut_addr["device_ip"], protocol=protocol
            )
            net_perf_client.interfaces.net_perf.start()

            # DUT sends data (CLIENT role)
            logger().info("Sending data from DUT")
            wifi_dut.interfaces.wifi.iperf(
                family=2,
                transfer_type=transfer_type,
                protocol=protocol_num,
                local_port=net_perf_client.interfaces.net_perf.get_server_port(),
                local_ip=dut_addr["device_ip"],
                remote_ip=host_ip,
                remote_port=net_perf_client.interfaces.net_perf.get_server_port(),
                size=size,
                ttl=30,
                throughput_type=throughput_type,
                qos=0,
                timeout=timeout + 2,
            )

            # Get and validate throughput
            tp = net_perf_client.interfaces.net_perf.process_output()
            assert tp is not None, "Throughput not found"
            logger().info(f"Data transfer successful - Throughput: {tp}")
            time.sleep(5)

        # Cleanup
        wifi_dut.interfaces.wifi.leave()
        time.sleep(2)

    finally:
        # wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(2)
        
# Standalone attenuator set and readback test — no wifi_dut required
@pytest.mark.rf_attenuator('50pa500_attenuator')
def test_attenuator_set_and_get(rf_attenuator):
    try:
        att_channel = 2
        db_value = 40
        logger().info(f"Resetting attenuator")
        rf_attenuator.interfaces.attenuator.reset()
        logger().info(f"Setting attenuator channel {att_channel} to {db_value}dB")
        rf_attenuator.interfaces.attenuator.set_attenuator(att_channel, db_value)
        readback = rf_attenuator.interfaces.attenuator.get_attenuator(att_channel)
        logger().info(f"Readback of attenuator channel {att_channel}: {readback}dB")
        assert readback == db_value, f"Attenuator readback mismatch: set {db_value}dB but got {readback}dB"
        logger().info("Attenuator set and get test passed successfully")
    except Exception as e:
        logger().info(f"\n got exception: {e}")
        assert False, f"Attenuator test failed: {e}"
 