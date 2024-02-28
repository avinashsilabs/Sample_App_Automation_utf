import time
import pytest
import requests


@pytest.mark.test_src_map_id('SM11908')
def test_openssl(openssl):
    # flush he messages, which are already there (like accept etc)
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
    print(messages)
    assert len(messages) == 1
    assert "Hello" in messages[0]

    openssl.interfaces.client.send_message("Hi")
    messages = openssl.interfaces.server.get_messages(1)
    print(messages)
    assert len(messages) == 1
    assert "Hi" in messages[0]


@pytest.mark.test_src_map_id('SM11912')
def test_server_stopped(openssl):
    # flush he messages, which are already there (like accept etc)
    openssl.interfaces.server.start()
    time.sleep(1)
    assert openssl.interfaces.server.is_running() is True
    openssl.interfaces.client.start()
    time.sleep(1)
    assert openssl.interfaces.client.is_running() is True
    openssl.interfaces.server.stop()
    time.sleep(1)
    assert openssl.interfaces.server.is_running() is False
    assert openssl.interfaces.client.is_running() is False


@pytest.mark.test_src_map_id('SM11916')
def test_server_not_running(openssl):
    openssl.interfaces.client.start()
    time.sleep(1)
    assert openssl.interfaces.client.is_running() is False


@pytest.mark.config(
    "openssl",
    client={
        "tls_version": "-tls1"
    }
)
@pytest.mark.test_src_map_id('SM11920')
def test_client_server_different_tls_version(openssl):
    openssl.interfaces.server.start()
    time.sleep(1)
    assert openssl.interfaces.server.is_running() is True
    openssl.interfaces.client.start()
    time.sleep(1)
    assert openssl.interfaces.client.is_running() is False
    assert openssl.interfaces.server.is_running() is True


@pytest.mark.config(
    "openssl",
    server={
        "http": True
    }
)
@pytest.mark.test_src_map_id('SM11924')
def test_http_server(openssl):
    openssl.interfaces.server.start()
    time.sleep(1)
    assert openssl.interfaces.server.is_running() is True
    session = requests.Session()
    method = "GET"
    index_path = "index.html"
    url = "https://localhost:5001/index.html"
    kwargs = {}
    kwargs["verify"] = False
    r = session.request(method, url, **kwargs)
    assert r.status_code == 200
