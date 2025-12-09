import time
import pytest
from typing import Union
from websocket_server import (
    OPCODE_PING,
    OPCODE_PONG,
)

@pytest.mark.http_server("secondary_raspi")
@pytest.mark.http_client("secondary_raspi")
def test_http_server_and_linux_client_post(
    http_server, http_client, logger
):
    method = "POST"
    index_path = "cgi-bin/cgi_example.py"
    content = {"example": "data"}
    # Extract server config as dict to avoid RPC serialization issues
    server_config = {
        "tls_enabled": http_server.interfaces.http.tls_enabled,
        "hostname_or_ip_address": http_server.interfaces.http.hostname_or_ip_address,
        "port": http_server.interfaces.http.port,
        "tls_ca_chain": http_server.interfaces.http.tls_ca_chain
    }
    status, resp_content = http_client.interfaces.http_client.http_request(
        server_config, method, index_path, content
    )
    logger.info(status)
    logger.info(resp_content)

@pytest.mark.skip(reason="Uses pytest marker for http_server, needs to be adapted for RPC")
@pytest.mark.http_server("secondary_raspi")
@pytest.mark.config("http_server", auto_start=False)
def test_http_server_and_linux_client_get_with_config_ports(http_server, http_client, logger):
    ports = (200, 201, 202, 203)
    for index in range(3):
        port = ports[index]
        http_server.interfaces.http.start_server(port=port)
        method = "GET"
        index_path = "index.html"
        status, resp_content = http_client.interfaces.http.http_request(
            http_server.interfaces.http, method, index_path
        )
        logger.info(status)
        logger.info(resp_content)
        http_server.interfaces.http.stop_server()


@pytest.mark.http_server("secondary_raspi")
@pytest.mark.http_client("secondary_raspi")
def test_websocket_server_and_linux_client(
    http_server, http_client, logger
):
    # Note: Callback registration doesn't work over RPC because Python methods
    # cannot be serialized. For RPC scenarios, server-side events are not observable
    # from the client side. The test still verifies WebSocket communication works.
    server_config = {
    "tls_enabled": http_server.interfaces.http.tls_enabled,
    "hostname_or_ip_address": http_server.interfaces.http.hostname_or_ip_address,
    "port": http_server.interfaces.http.port,
    "tls_ca_chain": http_server.interfaces.http.tls_ca_chain
    }

    http_server.interfaces.http.create_websocket_event_handler()

    http_server.interfaces.http.setup_websocket_callbacks()

    http_client.interfaces.http_client.websocket_connect(
        server_config, "/websocket"
    )
    time.sleep(0.1)
    is_client_connected = http_server.interfaces.http.get_ws_handler_client_connected
    assert is_client_connected
    http_client.interfaces.http_client.websocket_send("Howdy!")
    time.sleep(0.1)
    is_message_received = http_server.interfaces.http.get_ws_handler_message_received
    assert is_message_received == "Howdy!"
    http_server.interfaces.http.send_message_to_websocket_clients("Hello!")
    time.sleep(0.1)
    data = http_client.interfaces.http_client.websocket_receive()
    time.sleep(0.1)
    assert data == "Hello!"

    http_server.interfaces.http.send_opcode_to_websocket_clients(OPCODE_PING)
    time.sleep(0.1)
    data = http_client.interfaces.http_client.websocket_receive()
    time.sleep(0.1)
    assert data == OPCODE_PING

    http_server.interfaces.http.send_opcode_to_websocket_clients(OPCODE_PONG)
    time.sleep(0.1)
    data = http_client.interfaces.http_client.websocket_receive()
    time.sleep(0.1)
    assert data == OPCODE_PONG

    http_client.interfaces.http_client.websocket_close()
    time.sleep(0.1)
    is_client_disconnected = http_server.interfaces.http.get_ws_handler_client_disconnected
    assert is_client_disconnected
    
@pytest.mark.http_server("secondary_raspi")
@pytest.mark.http_client("raspi_http_client")
def test_http_server_and_linux_client_post_with_local_http_client(
    http_server, http_client, logger
):
    method = "POST"
    index_path = "cgi-bin/cgi_example.py"
    content = {"example": "data"}
    # Extract server config as dict to avoid RPC serialization issues
    server_config = {
        "tls_enabled": http_server.interfaces.http.tls_enabled,
        "hostname_or_ip_address": http_server.interfaces.http.hostname_or_ip_address,
        "port": http_server.interfaces.http.port,
        "tls_ca_chain": http_server.interfaces.http.tls_ca_chain
    }
    status, resp_content = http_client.interfaces.http_client.http_request(
        server_config, method, index_path, content
    )
    logger.info(status)
    logger.info(resp_content)
