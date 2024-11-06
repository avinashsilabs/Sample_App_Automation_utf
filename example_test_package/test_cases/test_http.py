import pytest


@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("raspi_http_client")
def test_http_server_and_linux_client_post(
    http_server, http_client, wifi_access_point, logger
):
    method = "POST"
    index_path = "cgi-bin/cgi_example.py"
    content = {"example": "data"}
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path, content
    )
    logger.info(status)
    logger.info(resp_content)


@pytest.mark.wifi_access_point("raspi_wifi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.http_client("raspi_http_client")
def test_http_server_and_linux_client_put(
    http_server, http_client, wifi_access_point, logger
):
    method = "PUT"
    index_path = "cgi-bin/cgi_example.py"
    content = {"example": "data"}
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path, content
    )
    logger.info(status)
    logger.info(resp_content)

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
            http_server.interfaces.http, method, index_path
        )
        logger.info(status)
        logger.info(resp_content)
        http_server.interfaces.http.stop_server()

@pytest.mark.http_server("python_http_server")
@pytest.mark.parametrize("index_path, method, content", [
    ("index.html", "POST", {"key": "test"}),
    ("index.html", "POST", {"key": "test"}),
    ("index.html", "PUT", {"key": "test"}),
    ("index.html", "PUT", {"key": "test"}),
    ("index.html", "GET", "")
])
def test_python_http_server(http_server,index_path,http_client, method, content, logger):
    status, content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path, content
    )
    logger.info(f"response code: {status}")
    logger.info(f"response content: {content}")