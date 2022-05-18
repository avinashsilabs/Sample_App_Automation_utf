# Test author: Vinod.G
# Test suite: AWS_IOT test suite
import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CoexMode,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116PowerSaveModes,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
    DeviceConstants,
    )
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping
from utf.utils.stopwatch import Stopwatch

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


def join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    for count in range(1, 3):
        try:
            scan_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Scanning to the Wifi Access Point")
            wifi_dut.interfaces.wifi.scan(ssid=None)
            scan_fail = 0
            break
        except:
            logger.info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
            time.sleep(1)
    if scan_fail:
        logger.info(f"Scanning to the AP has failed")
        assert scan_fail == 0, "Scanning to the AP is failed"

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")

    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=10,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
    if join_fail:
        logger.info(f"Joining to the AP has failed")
        assert join_fail == 0, "Joining to the AP is failed"
    for count in range(1, 3):
        ip_fail = 1
        try:
            # DUT gets ipaddress through DHCP process after start_ip API is executed
            logger.info("DUT gets ipaddress through DHCP ")
            ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            ip_fail = 0
            break
        except:
            logger.info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    if ip_fail:
        logger.info(f"DUT unable to get IP address")
        assert ip_fail == 0, "ip setting in DUT has failed"
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.DNSClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.RsaKeyWith4096Support | RS9116ExtCustomFeatureBitMap.SslCertWith4096Support | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
            "set_send_feature_frame": True,
            "ca_cert": ["start_field.pem"],
            "client_cert": ["client-certificate.crt"],
            "client_key": ["private-key.key"],
            }
        )
    ]


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_connect_sub_publish_TC19548(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    topic_1 = "sdk/test/Python"
    message = ['{"message": "my payload"}'] * 10

    capture_filename = "test_aws_connect_sub_publish_TC19548"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)

    for count in range(0, 3):
        try:
            aws_fail = 1
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    if aws_fail:
        logger.info(f"Connecting to AWS server is failed")
        assert aws_fail == 0, "JConnecting to AWS server is failed"
    logger.info(f"Connecting to AWS server is successful")
    time.sleep(2)
    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

    for msg in message:
        logger.info(f"Sending message {msg} on topic {topic_1}")
        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, msg, 0
            )
        time.sleep(1)
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()

    count = 0
    if len(events):
        logger.info(f"Number of messages received on subscribed topic {topic_1} -> {len(events)}")
        for event in events:
            assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
            assert message[count] == event.event_data.payload, "sent and received messages are not matching"
            count = count + 1
            logger.info(f"Message->{count} received on topic {event.event_data.topic} -> {event.event_data.payload}")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_connect_after_wifi_reconnection_TC4053(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    topic_1 = "sdk/test/Python"
    message = ['{"message": "my payload"}'] * 10
    capture_filename = "test_aws_connect_after_wifi_reconnection_TC4053"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
    wifi_dut.interfaces.wifi.leave()
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    wifi_dut.interfaces.wifi.start_ip()
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    for count in range(0, 3):
        try:
            aws_fail = 1
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    if aws_fail:
        logger.info(f"Connecting to AWS server is failed")
        assert aws_fail == 0, "JConnecting to AWS server is failed"
    logger.info(f"Connecting to AWS server is successful")

    time.sleep(2)
    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

    for msg in message:
        logger.info(f"Sending message {msg} on topic {topic_1}")
        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, msg, 0
            )
        time.sleep(1)
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()

    count = 0
    if len(events):
        logger.info(f"Number of messages received on subscribed topic {topic_1} -> {len(events)}")
        for event in events:
            assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
            assert message[count] == event.event_data.payload, "sent and received messages are not matching"
            count = count + 1
            logger.info(f"Message->{count} received on topic {event.event_data.topic} -> {event.event_data.payload}")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
    wifi_dut.interfaces.wifi.aws_iot_disconnect()
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("iterations", [10])
def test_aws_rejoin_fail_TC19549(wifi_sniffer, wifi_access_point, wifi_dut, logger, iterations):
    topic_1 = "sdk/test/Python"
    message = '{"message": "my payload"}'
    rejoin_msg = 0
    since_time = 0
    capture_filename = "test_aws_rejoin_fail_TC19549"
    for count in range(1, (iterations + 1)):
        if count == 1:
            dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)
        else:
            logger.info("Disable Wireless in AP")
            wifi_access_point.interfaces.wifi.stop_ap()
            logger.info("Wait for 120 seconds")
            time.sleep(120)
            logger.info("Enable Wireless in AP")
            wifi_access_point.interfaces.wifi.start_ap()
            events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        since_time = event.timestamp + 1
            assert rejoin_msg == 1, "rejoin error not found even AP is switched off"
            logger.info(f"Rejoin error is sent by DUT when wireless is disabled in AP for 120 seconds")
            wifi_dut.interfaces.wifi.associated = False
            rejoin_msg = 0
            for count_join in range(1, 3):
                try:
                    join_fail = 1
                    # DUT connects to AP after join_ap API is executed
                    logger.info("Joining to the Wifi Access Point")
                    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
                    join_fail = 0
                    break
                except:
                    logger.info(f"Joining to the Wifi Access point is failed. retry count -> {count_join}")
                    time.sleep(1)
            if join_fail:
                logger.info(f"Joining to the AP has failed")
                assert join_fail == 0, "Joining to the AP is failed"
            for count_ip in range(1, 3):
                ip_fail = 1
                try:
                    # DUT gets ipaddress through DHCP process after start_ip API is executed
                    logger.info("DUT gets ipaddress through DHCP ")
                    ip_address = wifi_dut.interfaces.wifi.start_ip(timeout=60)
                    ip_fail = 0
                    break
                except:
                    logger.info(f"Get IP address through dhcp process is failed. retry count -> {count_ip}")
                    time.sleep(1)
            if ip_fail:
                logger.info(f"DUT unable to get IP address")
                assert ip_fail == 0, "ip setting in DUT has failed"

            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)

        for count_aws in range(0, 3):
            try:
                aws_fail = 1
                wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
                aws_fail = 0
                break
            except:
                logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
                time.sleep(1)
        if aws_fail:
            logger.info(f"Connecting to AWS server is failed")
            assert aws_fail == 0, "JConnecting to AWS server is failed"
        logger.info(f"Connecting to AWS server is successful")

        time.sleep(2)
        wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, message, 0
            )
        time.sleep(2)
        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
        if len(events):
            for event in events:
                since_time = event.timestamp + 1
                assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
                assert message == event.event_data.payload, "sent and received messages are not matching"

        wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
        wifi_dut.interfaces.wifi.aws_iot_disconnect()
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_server_not_respond_TC4062(wifi_sniffer, wifi_access_point, wifi_dut, logger):
    topic_1 = "sdk/test/Python"
    message = ['{"message": "my payload"}'] * 10
    capture_filename = "test_aws_server_not_respond_TC4062"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)

    with pytest.raises(WlanError) as exc_info:
        wifi_dut.interfaces.wifi.aws_iot_connect(hostname="www.google.com", load_cert=False)
    assert exc_info.value.error_code == 0x0021, "DUT sent wrong error code, expected is 0x0021"
    logger.info(f"DUT sent error code {exc_info.value.error_code} when server is not responding which is expected")

    for count in range(0, 3):
        try:
            aws_fail = 1
            wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
            aws_fail = 0
            break
        except:
            logger.info(f"Connecting to AWS server is failed. retry count->{count + 1}")
            time.sleep(1)
    if aws_fail:
        logger.info(f"Connecting to AWS server is failed")
        assert aws_fail == 0, "JConnecting to AWS server is failed"
    logger.info(f"Connecting to AWS server is successful")

    time.sleep(2)
    wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

    for msg in message:
        logger.info(f"Sending message {msg} on topic {topic_1}")
        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, msg, 0
            )
        time.sleep(1)
    time.sleep(10)
    events = wifi_dut.interfaces.wifi.get_async_events()

    count = 0
    if len(events):
        logger.info(f"Number of messages received on subscribed topic {topic_1} -> {len(events)}")
        for event in events:
            assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
            assert message[count] == event.event_data.payload, "sent and received messages are not matching"
            count = count + 1
            logger.info(f"Message->{count} received on topic {event.event_data.topic} -> {event.event_data.payload}")
    wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
    wifi_dut.interfaces.wifi.aws_iot_disconnect()

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("test_run_time", [1800])
def test_aws_connect_disconnect_sequence_TC19552(wifi_sniffer, wifi_access_point, wifi_dut, logger, test_run_time):
    topic_1 = "sdk/test/Python"
    message = '{"message": "my payload"}'
    since_time = 0
    capture_filename = "test_aws_connect_disconnect_sequence_TC19552"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_access_point, wifi_dut, capture_filename, logger)

    sw = Stopwatch()
    logger.info(f"Running the aws connect and disconnect test for {test_run_time} seconds")
    while sw.elapsed_sec < test_run_time:
        for count_aws in range(0, 3):
            try:
                aws_fail = 1
                wifi_dut.interfaces.wifi.aws_iot_connect(load_cert=False)
                aws_fail = 0
                break
            except:
                logger.info(f"Connecting to AWS server is failed. retry count->{count_aws + 1}")
                time.sleep(1)
        if aws_fail:
            logger.info(f"Connecting to AWS server is failed")
            assert aws_fail == 0, "JConnecting to AWS server is failed"
        logger.info(f"Connecting to AWS server is successful")

        time.sleep(2)
        wifi_dut.interfaces.wifi.aws_iot_subscribe(topic_1, 0)

        wifi_dut.interfaces.wifi.aws_iot_publish(
            topic_1, message, 0
            )
        time.sleep(2)
        events = wifi_dut.interfaces.wifi.get_async_events(since_time=since_time)
        if len(events):
            for event in events:
                since_time = event.timestamp + 1
                assert topic_1 == event.event_data.topic, "message is not received on subscribed topic"
                assert message == event.event_data.payload, "sent and received messages are not matching"

        wifi_dut.interfaces.wifi.aws_iot_unsubscribe(topic_1)
        wifi_dut.interfaces.wifi.aws_iot_disconnect()
        time.sleep(5)
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger.info("Stop Sniffer finally")
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
