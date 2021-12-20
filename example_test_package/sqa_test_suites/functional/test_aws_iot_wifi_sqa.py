# Test author: Vinod.G
# Test suite: AWS_IOT test suite
import time
import pytest
from devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveModes
    )
from devices.rs911x import RS9116AsyncEventType
from interfaces.wifi import WlanError

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Connect to the AWS MQTT server
        5. Send or receive data on MQTT and verify packet loss tests 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
"""
#
pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                              | RS9116TCPIPFeatureBitMap.SSL
                              | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                              | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.SSLCertBypass | RS9116ExtTCPIPFeatureBitMap.Default,
            },
        ),
    ]


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_connect_sub_publish_TC4049(wifi_access_point, wifi_dut):
    topic_1 = "sdk/test/Python"
    message = '{"message": "my payload"}'

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.aws_iot_connect()
    time.sleep(2)
    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

    wifi_dut.interfaces.wifi.aws_iot_publish(
        topic_1, message, 0
        )
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()

    if len(events):
        for event in events:
            assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
            assert message == event.event_data.payload, "sent and received messages are not matching"


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_connect_after_wifi_reconnection_TC4053(wifi_access_point, wifi_dut):
    topic_1 = "sdk/test/Python"
    message = '{"message": "my payload"}'
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()

    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    wifi_dut.interfaces.wifi.aws_iot_connect()
    time.sleep(2)
    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

    wifi_dut.interfaces.wifi.aws_iot_publish(
        topic_1, message, 0
        )
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()

    if len(events):
        for event in events:
            assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
            assert message == event.event_data.payload, "sent and received messages are not matching"


@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['associated'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_rejoin_fail_TC4054(wifi_access_point, wifi_dut):
    topic_1 = "sdk/test/Python"
    message = '{"message": "my payload"}'
    rejoin_msg = 0
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(120)
    wifi_access_point.interfaces.wifi.start_ap()
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.RejoinError:
                rejoin_msg = 1
    assert rejoin_msg == 1, "rejoin error not found even AP is switched off"

    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    wifi_dut.interfaces.wifi.aws_iot_connect()
    time.sleep(2)
    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

    wifi_dut.interfaces.wifi.aws_iot_publish(
        topic_1, message, 0
        )
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()

    if len(events):
        for event in events:
            assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
            assert message == event.event_data.payload, "sent and received messages are not matching"


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_server_not_respond_TC4062(wifi_access_point, wifi_dut):
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.aws_iot_connect(hostname="www.google.com")
    assert exc_info.value.error_code == 0xFFFFFFFD, "DUT sent wrong error code, expected is 0xFFFFFFFD"


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.parametrize('repeat', [5])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_aws_connect_disconnect_sequence_TC4057(wifi_access_point, wifi_dut, repeat):
    topic_1 = "sdk/test/Python"
    message = '{"message": "my payload"}'
    # DUT connects to AP after join_ap API is executed
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    for count in range(0, repeat):
        wifi_dut.interfaces.wifi.aws_iot_connect()
        wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, message, 0
            )
        wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
        wifi_dut.interfaces.wifi.aws_iot_disconnect()
        time.sleep(60)
