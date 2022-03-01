import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CertificateType,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
)
from utf.utils import get_tls_certificate_dir
import os
import socket


pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("dlink_810"),
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


def test_socket(wifi_networked_dut):

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

    # open 4 sockets to DUT, but we'll only use the last one
    wf.open_tcp_client_socket(protocol=0)
    wf.open_tcp_client_socket(protocol=0)
    wf.open_tcp_client_socket(protocol=0)
    sock = wf.open_tcp_client_socket(protocol=1)  # protocol=1 enables SSL
    wf.bind(8883, "0.0.0.0", sock)
    ip_addr = socket.gethostbyname("a2lqafhldpb41r-ats.iot.us-east-1.amazonaws.com")
    wf.connect(socket_id=sock, server_ip=ip_addr, server_port=8883, timeout=10)
