import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CertificateType, RS9116TCPIPFeatureBitMap,
)
from utf.utils import get_tls_certificate_dir
import os

# Mark all tests in this module with 'framework_integration_test'
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.config(
          "wifi_dut",
          wifi={
              "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                                | RS9116TCPIPFeatureBitMap.SSL
                                | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                                | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
          },
      )
]


@pytest.mark.parametrize("cert_type, cert_filename", [
    (RS9116CertificateType.SSLCACertificate, 'ca-cert-with-crlf.pem')
])
def test_cert_load(wifi_dut, cert_type, cert_filename):
    wifi_dut.interfaces.wifi.set_ssl_certificate(
        eval(cert_type),
        os.path.join(get_tls_certificate_dir(), cert_filename),
    )
