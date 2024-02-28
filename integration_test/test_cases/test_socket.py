import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType, DeviceConstants
)
from utf.utils import get_tls_certificate_dir
import os
import socket

pytestmark = [
    pytest.mark.framework_integration_test,
    # pytest.mark.wifi_access_point("switched_ap"),
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                              | RS9116TCPIPFeatureBitMap.SSL
                              | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                              | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
            # Note that SSL cert bypass is required to avoid SSL handshake error.
            # It is unclear if this is a bug in the AWS SAPI network wrapper
            # or in the 9116 firmware
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.SSLCertBypass,
        },
    ),
]

@pytest.mark.test_src_map_id('SM11953')
def test_socket_basic(wifi_networked_dut, remote_socket, logger):
    device_ip = wifi_networked_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)

    remote_socket.interfaces.socket.start_server()

    sock = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()

    assert sock == 0, f"socket id received is wrong, expected is 0"

    wifi_networked_dut.interfaces.wifi.bind(sock, device_ip, 5001)
    wifi_networked_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
    wifi_networked_dut.interfaces.wifi.send(sock, 50)

    wifi_networked_dut.interfaces.wifi.close_socket(sock)
    remote_socket.interfaces.socket.socket_close_indication(1)
    wifi_networked_dut.interfaces.wifi.leave()

@pytest.mark.skip
@pytest.mark.parametrize('iteration', [0,1,2,3,4,5])
@pytest.mark.test_src_map_id('SM11958')
def test_socket(wifi_networked_dut, iteration):

    wifi_networked_dut.interfaces.wifi.set_ssl_certificate(
        RS9116CertificateType.SSLCACertificate,
        os.path.join(get_tls_certificate_dir(), "AWS-IoT-root-CA.crt"),
    )
    wifi_networked_dut.interfaces.wifi.set_ssl_certificate(
        RS9116CertificateType.SSLClientCertificate,
        os.path.join(get_tls_certificate_dir(), "python-thing-certificate.pem.crt"),
    )
    wifi_networked_dut.interfaces.wifi.set_ssl_certificate(
        RS9116CertificateType.SSLClientPrivateKey,
        os.path.join(get_tls_certificate_dir(), "python-thing-private.pem.key"),
    )

    wf = wifi_networked_dut.interfaces.wifi
    wf.open_tcp_client_socket(protocol=0) # protocol=1 enables SSL
    wf.open_tcp_client_socket(protocol=0) # protocol=1 enables SSL
    wf.open_tcp_client_socket(protocol=0) # protocol=1 enables SSL
    sock = wf.open_tcp_client_socket(protocol=1) # protocol=1 enables SSL
    wf.bind(8883, '0.0.0.0', sock)
    ip_addr = socket.gethostbyname('a2lqafhldpb41r-ats.iot.us-east-1.amazonaws.com')
    wf.connect(socket_id=sock, server_ip=ip_addr, server_port=8883, timeout=10)



