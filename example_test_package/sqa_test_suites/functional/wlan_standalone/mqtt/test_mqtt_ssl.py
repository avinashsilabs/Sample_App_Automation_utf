# Test author: Vinod.G
# Test suite: MQTT_INTERNAL
import time
import pytest
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116AsyncEventType,
    RS9116PowerSaveModes,
    RS9116MqttQos,
    MQTTHeaderLength,
    RS9116PowerSaveProcedureTypes,
    RS9116CustomFeatureBitMap,
    RS9116ExtCustomFeatureBitMap
    )
from utf.utils.stopwatch import Stopwatch
import string
import filecmp
import os
import random
from utf import UtfDatabaseProperties
from threading import Thread
from utf.utils import mac_address_to_string
from utf.utils.iperf.iperf_utils import ping
from datetime import datetime

"""The testcases added in this file run below test steps for DUT-RS9116
        1. Configuration of DUT in 2G/5G : BGN
        2. Load ssl certificates into the DUT
        3. Association of Third party AP's
        4. Get the valid IP address
        5. Open MQTT server in the Raspberry pi
        6. Connect to the MQTT server from the DUT
        7. Connect to the MQTT server from the Raspberry pi
        8. Send or receive data on MQTT and verify packet loss tests 
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

Note: The test cases added in the file works only in AT mode
"""


def join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger):
    ping_count = 10
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f"DUT firmware version: {result}")
    logger.info(f"Start sniffer capture on channel {wifi_access_point.interfaces.wifi.channel}")
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )

    mac_address = mac_address_to_string(wifi_dut.interfaces.wifi.mac_address)

    logger.info(f"DUT MAC_Address: {mac_address}")
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap"
        )
    for count in range(1, 3):
        try:
            join_fail = 1
            # DUT connects to AP after join_ap API is executed
            logger.info("Joining to the Wifi Access Point")
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            join_fail = 0
            break
        except:
            wifi_dut.interfaces.wifi.initialized = False
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

    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_address)
    logger.info(f"DUT ip : {device_ip}")
    logger.info(f"Initiating ping to DUT ip {device_ip}")
    status = ping(device_ip, 10)
    if status == 1:
        logger.info(f"ping to DUT is successful")
    else:
        logger.info(f"ping to DUT is failed")
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    logger.info(f"Initiating ping to DUT ip {device_ip} after power save")
    ping(device_ip, ping_count)
    return mac_address


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(1)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(wait_time)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()



pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_authentication_ssl_TC19258',
                                                       test_case_id='TC19258',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_mqtt_authentication_ssl_TC19258(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

    capture_filename = "test_mqtt_authentication_ssl_TC19258"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1, qos=RS9116MqttQos.QOS1)
    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic2, qos=RS9116MqttQos.QOS1)
    except:
        time.sleep(1)

    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), qos=RS9116MqttQos.QOS1)
    time.sleep(1)
    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode(), qos=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by DUT"
    assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
    assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                 "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT received message with wrong QOS. expected is QOS1"
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break

    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic2, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
    assert msgs[0].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                 "message " \
                                                 "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 1
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0
    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_rx_after_rejoin_ssl_TC19271',
                                                       test_case_id='TC19271',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_after_rejoin_ssl_TC19271(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"

    capture_filename = "test_mqtt_rx_after_rejoin_ssl_TC19271"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(1)

    try:
        if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
            logger.info(f"'{wifi_dut.name}' is connected to MQTT server")
    except:
        time.sleep(1)

    send_count = 0
    ap_power_off = 0
    send_pkts = int((total_bytes / publish_len))

    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)
                if ap_power_off:
                    ap_power_off = 0
                    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 10, logger), )
                    thread.start()
                try:
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(120)
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                send_count = send_count + 1
                if send_count == int((send_pkts / 4)):
                    ap_power_off = 1

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)
    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_publish_while_rejoin_ssl_TC19274',
                                                       test_case_id='TC19274',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_while_rejoin_ssl_TC19274(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    count_rejoin = set()
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"

    capture_filename = "test_mqtt_publish_while_rejoin_ssl_TC19274"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
            logger.info(f"'{mqtt_client.name}' is connected to MQTT server")
    except:
        time.sleep(1)

    send_count = 0
    ap_power_off = 0
    send_pkts = int((total_bytes / publish_len))

    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)
                if ap_power_off:
                    ap_power_off = 0
                    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 10, logger), )
                    thread.start()
                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                    events = wifi_dut.interfaces.wifi.get_async_events()
                    rejoin_error_events = [event for event in events if
                                           event.event_type == RS9116AsyncEventType.RejoinError]
                    if len(rejoin_error_events):
                        count_rejoin.add(str(rejoin_error_events[0]))
                except:
                    logger.info("Exception Occured")
                    assert False
                finally:
                    if(len(count_rejoin)):
                        logger.info("***** Rejoin Error Occured, publishing data again ****")
                        time.sleep(60)
                        wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                count_rejoin.clear()
                send_count = send_count + 1
                if send_count == int((send_pkts / 4)):
                    ap_power_off = 1

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)

    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_rx_ssl_TC19285',
                                                       test_case_id='TC19285',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_ssl_TC19285(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"

    capture_filename = "test_mqtt_rx_ssl_TC19285"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{wifi_dut.name}' is connected to MQTT server")

    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)

                try:
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)

    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_publish_1mb_file_ssl_TC19286',
                                                       test_case_id='TC19286',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1200, 1024000, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_1mb_file_ssl_TC19286(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"

    capture_filename = "test_mqtt_publish_1mb_file_ssl_TC19286"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
            logger.info(f"'{mqtt_client.name}' is connected to MQTT server")
    except:
        time.sleep(1)

    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)

                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)

    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_publish_max_len_ssl_TC19287',
                                                       test_case_id='TC19287',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1370, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_max_len_ssl_TC19287(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"

    capture_filename = "test_mqtt_publish_max_len_ssl_TC19287"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
            logger.info(f"'{mqtt_client.name}' is connected to MQTT server")
    except:
        time.sleep(1)
    publish_len = (1370 - len(topic1) - MQTTHeaderLength.Length)
    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)

                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)

    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.leave()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_publish_max_len_ssl_ecdsa_TC19290',
                                                       test_case_id='TC19290',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca_ecdsa.crt"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1370, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls_ecdsa")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_publish_max_len_ssl_ecdsa_TC19290(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_publish_max_len_ssl_ecdsa_TC19290"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    try:
        if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
            mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
            logger.info(f"'{mqtt_client.name}' is connected to MQTT server")
    except:
        time.sleep(1)
    publish_len = (1370 - len(topic1) - MQTTHeaderLength.Length)
    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)

                try:
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)

    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()


# @pytest.mark.config(
#     "wifi_dut",
#     wifi=
#     {
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
#         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#         "ca_cert": "AWS-IoT-root-CA.crt",
#         "client_cert": "python-thing-certificate.pem.crt",
#         "client_key": "python-thing-private.pem.key"
#
#         },
#     )
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
# @pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# @pytest.mark.mqtt_server("static_mqtt_broker")
# # The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos0
# def test_mqtt_qos1_aws_connect_sub_publish_testcase_28(
#         mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
#         ):
#     topic_wild = "mytesttopic/#"
#     topic1 = "mytesttopic/1"
#     topic2 = "mytesttopic/2"
#     # The api returns 100 bytes of random data
#     message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
#     # The api returns 200 bytes of random data
#     message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))
#     # DUT connects to AP after join_ap API is executed
#     wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#     # DUT gets ipaddress through DHCP process after start_ip API is executed
#     wifi_dut.interfaces.wifi.start_ip()
#     # The below api puts DUT to power save
#     wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
#     wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
#     client_devices = [wifi_dut, mqtt_client]
#     # Both DUT and third-party mqtt client connects to MQTT server
#     for device in client_devices:
#         device.interfaces.mqtt.mqtt_client_connect_to_server(
#             mqtt_server.interfaces.mqtt
#             )
#
#     # Both DUT and third-party mqtt client subscribe on topic mytesttopic/#
#     for device in client_devices:
#         sw = Stopwatch()
#         while sw.elapsed_sec < 5:
#             time.sleep(0.1)
#             if device.interfaces.mqtt.mqtt_client_is_connected:
#                 device.interfaces.mqtt.mqtt_client_subscribe(topic_wild)
#                 logger.info(f"'{device.name}' is connected to MQTT server")
#                 break
#         else:
#             assert (
#                 device.interfaces.mqtt.mqtt_client_is_connected
#             ), f"Client '{device.name}' did not connect to MQTT server"
#
#     # publish a message with the dut
#     wifi_dut.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode())
#     # publish a message with the third-party mqtt client
#     mqtt_client.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode())
#
#     for device in client_devices:
#         # allow some time for both clients to receive all messages
#         sw = Stopwatch()
#         msgs = []
#         while sw.elapsed_sec < 10:
#             time.sleep(0.1)
#             # Both DUT and mqtt client receive messages
#             msgs = device.interfaces.mqtt.mqtt_client_get_received_messages()
#             if len(msgs) == 2:
#                 break
#
#         assert len(msgs) == 2, "No message is received by DUT and mqtt-client"
#         assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
#         assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
#                                                      "received is wrong"
#         assert msgs[0].qos == RS9116MqttQos.QOS0, "DUT received message with wrong QOS. expected is QOS0"
#         assert msgs[1].topic == topic2, "No message received by mqtt-client on subscribed topic"
#         assert msgs[1].qos == RS9116MqttQos.QOS0, "DUT sent message with wrong QOS. expected is QOS0"
#         assert msgs[1].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
#                                                      "message " \
#                                                      "received is wrong"
#
#     # The API returns asynchronous messages received by DUT
#     events = wifi_dut.interfaces.wifi.get_async_events()
#     assert len(events) == 2
#     # The API returns asynchronous messages received by DUT
#     events = wifi_dut.interfaces.wifi.get_async_events()
#     assert len(events) == 0

pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_mqtt_rx_ssl_ecdsa_TC19291',
                                                       test_case_id='TC19291',
                                                       notes='test notes'))
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "ca_cert": "ca_ecdsa.crt"
        }
    )
@pytest.mark.parametrize("publish_len, total_bytes, pkt_delay", [(1000, 102400, 0.5)])
@pytest.mark.mqtt_server("raspi_mosquitto_tls_ecdsa")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "powersave_disable", "disassociated"])
def test_mqtt_rx_ssl_ecdsa_TC19291(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger, publish_len, total_bytes, pkt_delay
        ):
    current_time = time.time()
    topic_wild = "mytesttopic/#"
    topic1 = "mytesttopic/1"
    capture_filename = "test_mqtt_rx_ssl_ecdsa_TC19291"
    dut_mac_address = join_get_ip(wifi_sniffer, wifi_dut, wifi_access_point, capture_filename, logger)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    temp_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=total_bytes))
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    tx_file = "./reports/" + capture_filename + "_tx_file" + file_time_stamp + ".txt"
    with open(tx_file, "w") as temp:
        temp.write(temp_buffer)

    client_devices = [wifi_dut, mqtt_client]

    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)

    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic_wild, qos=RS9116MqttQos.QOS1)
        logger.info(f"'{wifi_dut.name}' is connected to MQTT server")

    with open(tx_file, "r") as temp:
        while 1:
            buffer_length = publish_len
            buffer = temp.read(buffer_length)
            if buffer == '':
                break
            else:
                # publish a message with the dut
                if pkt_delay:
                    time.sleep(pkt_delay)

                try:
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)
                except:
                    time.sleep(5)
                    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, buffer.encode(), qos=RS9116MqttQos.QOS1)

    sw = Stopwatch()
    msgs = []
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
    file_time_stamp = str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    rx_file = "./reports/" + capture_filename + "_rx_file" + file_time_stamp + ".txt"
    if len(msgs):
        with open(rx_file, "w") as recv:
            for pkt in msgs:
                if pkt.topic == topic1:
                    recv.write(pkt.payload.decode())

    if not os.path.exists(rx_file):
        logger.info("No MQTT data received at receiver")

    result = filecmp.cmp(tx_file, rx_file, shallow=False)

    assert result == True, "Data loss observed, Contents of tx file and rx file not matched"

    logger.info("Stop the sniffer")
    wifi_sniffer.interfaces.capture.stop_capture()
    validation = True
    packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
    snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
    assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
    logger.info(f"PS-POLL packets are captured in the sniffer")
    wifi_dut.interfaces.wifi.mqtt_client_close()
    wifi_dut.interfaces.wifi.leave()
