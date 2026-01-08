import time
import pytest
from typing import Union
from websocket_server import (
    OPCODE_PING,
    OPCODE_PONG,
)
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.mqtt.client.paho_client import ensure_mqtt_message

@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("raspi_http_client")
def test_http_server_and_linux_client_post(
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

#@pytest.mark.skip(reason="Uses pytest marker for http_server, needs to be adapted for RPC")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.config("http_server", auto_start=False)
def test_http_server_and_linux_client_get_with_config_ports(http_server, http_client, logger):
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
def test_websocket_server_and_linux_client(
    http_server, http_client, logger
):
    # Note: Callback registration doesn't work over RPC because Python methods
    # cannot be serialized. For RPC scenarios, server-side events are not observable
    # from the client side. The test still verifies WebSocket communication works.

    http_server.interfaces.http.create_websocket_event_handler()

    http_server.interfaces.http.setup_websocket_callbacks()

    http_client.interfaces.http.websocket_connect(
        http_server.interfaces.http.get_server_config(), "/websocket"
    )
    time.sleep(0.1)
    is_client_connected = http_server.interfaces.http.get_ws_handler_client_connected
    assert is_client_connected
    http_client.interfaces.http.websocket_send("Howdy!")
    time.sleep(0.1)
    is_message_received = http_server.interfaces.http.get_ws_handler_message_received
    assert is_message_received == "Howdy!"
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
    is_client_disconnected = http_server.interfaces.http.get_ws_handler_client_disconnected
    assert is_client_disconnected
    
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("local_http_client")
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
@pytest.mark.parametrize("index_path, method, content", [
    ("index.html", "POST", {"key": "test"}),
    ("index.html", "POST", {"key": "test"}),
    ("index.html", "PUT", {"key": "test"}),
    ("index.html", "PUT", {"key": "test"}),
    ("index.html", "GET", "")
])
def test_python_http_server(http_server, index_path, http_client, method, content, logger):
    status, content = http_client.interfaces.http.http_request(
        http_server.interfaces.http.get_server_config(), method, index_path, content
    )
    logger.info(f"response code: {status}")
    logger.info(f"response content: {content}")


@pytest.mark.mqtt_server("raspi_mosquitto")
def test_mqtt_server_and_linux_client(
    mqtt_server, mqtt_client,
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
    msg = ensure_mqtt_message(msgs[0])
    assert msg.topic == "my test topic"
    assert msg.payload == b"12345"

@pytest.mark.mqtt_server("raspi_mosquitto")
@pytest.mark.mqtt_client("local_mqtt_client")
def test_mqtt_server_and_linux_client_with_local_mqtt_client(
    mqtt_server, mqtt_client,
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
    msg = ensure_mqtt_message(msgs[0])
    assert msg.topic == "my test topic"
    assert msg.payload == b"12345"