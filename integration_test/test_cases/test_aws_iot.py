import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
)
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from queue import Empty as QueueEmpty

# Mark all tests in this module with 'framework_integration_test'
# and other required markers
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
            # Note that SSL cert bypass is required to avoid SSL handshake error.
            # It is unclear if this is a bug in the AWS SAPI network wrapper
            # or in the 9116 firmware
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.SSLCertBypass,
        },
    ),
]

@pytest.mark.firmware_app("test_aws")
def test_python_client(firmware_loader, wifi_access_point, aws_iot_dut):
    topic_1 = "sdk/test/Python"
    topic_2 = "sdk/test/java"
    aws_iot_dut.interfaces.aws_iot.aws_iot_connect()
    time.sleep(2)
    aws_iot_dut.interfaces.aws_iot.aws_iot_subscribe(topic_1, 0)
    aws_iot_dut.interfaces.aws_iot.aws_iot_subscribe(topic_2, 0)
    time.sleep(4)
    for _ in range(0, 5):
        aws_iot_dut.interfaces.aws_iot.aws_iot_publish(
            topic_1, '{"message": "my payload"}', 0
        )
        aws_iot_dut.interfaces.aws_iot.aws_iot_publish(
            topic_2, '{"message": "my payload"}', 0
        )
        time.sleep(1)
    aws_iot_dut.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
    aws_iot_dut.interfaces.aws_iot.aws_iot_unsubscribe(topic_2)
    time.sleep(2)
    aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()


@pytest.mark.firmware_app("test_aws")
def test_aws_device_shadow(firmware_loader, wifi_access_point, aws_iot_dut):
    aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_init()
    time.sleep(2)
    shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateAccepted
    ]
    for i in range(0, 10):
        aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_update(i + 70)
        try:
            shadow_update_accepted_event_queue.get(timeout=180)
        except QueueEmpty:
            assert False, "Did not receive an expected shadow update accepted event"
        time.sleep(10)


def test_aws_iot_client(aws_iot_client):
    topic_1 = "sdk/test/Python"
    topic_2 = "sdk/test/java"
    aws_iot_client.interfaces.aws_iot.aws_iot_connect()
    time.sleep(2)
    aws_iot_client.interfaces.aws_iot.aws_iot_subscribe(topic_1, 0)
    time.sleep(4)

    aws_iot_client.interfaces.aws_iot.aws_iot_publish(
        topic_1, '{"message": "my payload"}', 0
    )
    aws_iot_client.interfaces.aws_iot.aws_iot_publish(
        topic_2, '{"message": "my payload"}', 0
    )
    time.sleep(1)
    messages = aws_iot_client.interfaces.aws_iot.get_received_messages()
    assert len(messages) == 1
    assert messages[0].topic == "sdk/test/Python"
    aws_iot_client.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
    time.sleep(2)
    aws_iot_client.interfaces.aws_iot.aws_iot_disconnect()
