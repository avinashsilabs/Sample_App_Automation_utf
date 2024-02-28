import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
)
from utf.utils.stopwatch import Stopwatch

# Mark all tests in this module with 'framework_integration_test'
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("raspi_wifi"),
    pytest.mark.http_server("raspi_lighttpd")
]


@pytest.mark.parametrize("index_path, method, content", [
    ("cgi-bin/cgi_example.py", "POST", {"key1": 'value1', "key2": 'value2'}),
    ("cgi-bin/cgi_example.py", "PUT", {"key1": 'value1', "key2": 'value2'}),
    ("cgi-bin/cgi_example.py", "GET", None)
    ]
)
@pytest.mark.test_src_map_id('SM11873')
def test_http_server_and_linux_client(
    http_server, http_client, wifi_access_point, logger, index_path, method, content
):
    status, resp_content = http_client.interfaces.http.http_request(
        http_server.interfaces.http, method, index_path, content
    )
    logger.info(status)
    logger.info(resp_content)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.parametrize(
    "index_path", ["index_long_crlf.html", "index_long_lf.html"]
)
@pytest.mark.test_src_map_id('SM11878')
def test_http_server_and_dut_client(
    http_server, http_dut, wifi_access_point, logger, index_path
):
    status, content = http_dut.interfaces.http.http_get(
        http_server.interfaces.http, index_path
    )
    logger.info(status)
    logger.info(content)
