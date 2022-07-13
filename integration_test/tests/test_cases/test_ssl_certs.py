import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CertificateType,
)
from utf.utils import get_tls_certificate_dir
import os

# Mark all tests in this module with 'framework_integration_test'
pytestmark = [
    pytest.mark.framework_integration_test,
]


def test_cert_load(wifi_dut, cert_type, cert_filename):
    wifi_dut.interfaces.wifi.set_ssl_certificate(
        eval(cert_type),
        os.path.join(get_tls_certificate_dir(), cert_filename),
    )
