import pytest
from utf.utils.logger import get_logger


def logger():
    return get_logger(__name__)


@pytest.mark.test_src_map_id('TC0098050045')
def test_http_servers_fixture(http_client, http_servers):
    index_path = "cgi-bin/cgi_example.py"
    content = {"key1": 'value1', "key2": 'value2'}
    status, resp_content = http_client.interfaces.http.http_request(
    http_servers[0].interfaces.http, "POST", index_path, content
    )
    logger().info(status)
    logger().info(resp_content)
    content = None
    status, resp_content = http_client.interfaces.http.http_request(
    http_servers[0].interfaces.http, "GET", index_path, content
    )
    logger().info(status)
    logger().info(resp_content)
    status, resp_content = http_client.interfaces.http.http_request(
    http_servers[1].interfaces.http, "POST", index_path, content
    )
    logger().info(status)
    logger().info(resp_content)
    content = None
    status, resp_content = http_client.interfaces.http.http_request(
    http_servers[1].interfaces.http, "GET", index_path, content
    )
    logger().info(status)
    logger().info(resp_content)
