import time
import pytest
from typing import Union
from websocket_server import (
    OPCODE_PING,
    OPCODE_PONG,
)

# Mark all tests in this module with 'framework_integration_test'
pytestmark = [
    pytest.mark.framework_integration_test,
]


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


@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.test_src_map_id('SM11998')
def test_websocket_server_and_linux_client(
    http_server, http_client, wifi_access_point, logger
):
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
    http_client.interfaces.http.websocket_connect(
        http_server.interfaces.http, "/websocket"
    )
    time.sleep(0.1)
    assert ws_handler.client_connected
    http_client.interfaces.http.websocket_send("Howdy!")
    time.sleep(0.1)
    assert ws_handler.message_received == "Howdy!"

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
    assert ws_handler.client_disconnected
