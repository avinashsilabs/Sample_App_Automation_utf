import random
import re
import time
from _queue import Empty
from asyncio import QueueEmpty
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from retry import retry
from pyshark.packet.layer import Layer
from utf.interfaces.cli import CLITransportException
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Send message to server for long duration(12~hours) at certain interval(~55Sec)

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    Author: Vivek Verma
"""


class IopTcpIpSockets:
    def open_socket(self, wifi_associated_dut_with_sniffer, dut_ip) -> int:
        tcp_socket_id = wifi_associated_dut_with_sniffer.interfaces.wifi.open_tcp_client_socket()
        if isinstance(tcp_socket_id, int):
            logger().info(f"Socket open successfully : {tcp_socket_id}")
        else:
            logger().error(f"Unable to open socket id: {tcp_socket_id}")
            raise RuntimeError(tcp_socket_id)

        time.sleep(2)
        bind_response = wifi_associated_dut_with_sniffer.interfaces.wifi.bind(tcp_socket_id, dut_ip)
        if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
            logger().info(f"Bind socket successfully: {bind_response}")
        else:
            logger().error(f"Unable to bind socket: {bind_response}")
            raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_associated_dut_with_sniffer, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_associated_dut_with_sniffer.interfaces.wifi.connect(tcp_socket_id)
            logger().info(f"Connect response : {connect_response}")
            if connect_response.decode() == '':
                logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                if retry < retry_limit:
                    pass
            elif connect_response.decode().split(">")[1].strip() == 'success':
                logger().info(f"Socket connected successfully in {retry} try")
                connect_status = True
                break
            logger().info(f"Socket connected with server in: {retry + 1} time")
        return connect_status


@retry(Exception, delay=20, tries=20)
def connect_aws_server_from_dut(aws_iot_dut):
    status = False
    try:
        aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_init()
        status = True
    except Exception as err:
        logger().error(str(err))
        if "0x2" in str(err):
            logger().warning("AWS server is not reachable from DUT, Please check your internet connection")
            aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
        time.sleep(10)
    assert status, "Connecting to AWS server from DUT is failed"
    return status


@pytest.mark.skip()
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
            EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
    },
)
def test_tcp_socket_enhanced_max_psp(wifi_sniffer, wifi_associated_dut_with_sniffer, rf_attenuator, utf_constants):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 10
    count_disconnect, count_connect, count_rejoin = set(), set(), set()
    try:
        if isinstance(wifi_associated_dut_with_sniffer.interfaces.wifi, RSSAPICommands):
            wifi_associated_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)

            ip_result = wifi_associated_dut_with_sniffer.interfaces.wifi.start_ip()
            dut_ip = ip_result.ip.decode()
            logger().info(f"DUT ip address: {dut_ip}")

            """Applying Enhanced Max Power save"""
            logger().info(f"*****Enable Enhanced Max Power save in DUT******")
            wifi_associated_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_associated_dut_with_sniffer.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

            ap_ssid = wifi_associated_dut_with_sniffer.interfaces.wifi.ssid
            logger().info(f"AP_ssid {ap_ssid}")

            test_execution_time = utf_constants.get("time_duration")
            logger().info(f'\n\n ***** Time duration = {test_execution_time}\n\n')

            tcp_socket_id = tcp_socket_obj.open_socket(wifi_associated_dut_with_sniffer, dut_ip)
            time.sleep(5)
            connect_status = tcp_socket_obj.connect_socket(wifi_associated_dut_with_sniffer, tcp_socket_id)
            if connect_status is False:
                logger().info("Unable to connect with Server")
                assert connect_status

            """ Start time for long duration and send messages """
            end_time = datetime.now() + timedelta(hours=test_execution_time)
            start_time = datetime.now()

            while 1:
                if datetime.now() >= end_time:
                    close_response = wifi_associated_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                    logger().info(f"close_response: {close_response}")
                    break
                logger().info(datetime.now())
                send_response = wifi_associated_dut_with_sniffer.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                        time.sleep(55)

                events = wifi_associated_dut_with_sniffer.interfaces.wifi.get_async_events()
                connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
                disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
                rejoin_error_events = [event for event in events if
                                       event.event_type == RS9116AsyncEventType.RejoinError]
                if len(disconnect_events):
                    count_disconnect.add(str(disconnect_events[0]))
                if len(connect_events):
                    count_connect.add(str(connect_events[0]))
                if len(rejoin_error_events):
                    count_rejoin.add(str(rejoin_error_events[0]))

                """Validate connection when DUT disconnected from AP """
                if (datetime.now() < end_time) and len(disconnect_events):
                    logger().info('Validate connection when DUT disconnected from AP')
                    if len(disconnect_events):
                        count_disconnect.add(str(disconnect_events[0]))
                        logger().info(f' Disconnect Event = {count_disconnect}')
                    # if DUT disconnect from AP, it will wait till 130 seconds for reconnection and resume TCP/IP
                    # server connection
                    time.sleep(130)
                    events = wifi_associated_dut_with_sniffer.interfaces.wifi.get_async_events()
                    connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
                    if len(connect_events):
                        count_connect.add(str(connect_events[0]))
                        close_response = wifi_associated_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                        logger().info(f"close_response: {close_response}")
                        tcp_socket_id = tcp_socket_obj.open_socket(wifi_associated_dut_with_sniffer, dut_ip)
                        time.sleep(2)
                        tcp_socket_obj.connect_socket(wifi_associated_dut_with_sniffer, tcp_socket_id)
                    else:
                        logger().info("Unable to connect with AP after 130 seconds")
                        break
                elif 'status -1' in str(send_response):
                    logger().info("If Socket disconnected from server")
                    tcp_socket_obj.connect_socket(wifi_associated_dut_with_sniffer, tcp_socket_id)

    except (IndexError, CLITransportException, AssertionError):
        logger().info("Find exception")
        assert False

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        """Verification of connect or disconnect event"""
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
        rejoin_error_events = [event for event in events if event.event_type == RS9116AsyncEventType.RejoinError]
        if len(disconnect_events): count_disconnect.add(str(disconnect_events[0]))
        if len(connect_events): count_connect.add(str(connect_events[0]))
        if len(rejoin_error_events): count_rejoin.add(str(rejoin_error_events[0]))
        if count_connect: logger().info(f'Total no of connection={len(count_connect)}')
        if count_disconnect: logger().info(f'Total no of disconnect={len(count_disconnect)}')
        if count_rejoin: logger().info(f'Total no of Rejoin={len(count_rejoin)}')
        end_time = datetime.now()
        exact_execution_time = end_time - start_time
        logger().info(f"Total execution time of test case = {exact_execution_time}")
    wifi_associated_dut_with_sniffer.interfaces.wifi.leave()


@pytest.mark.skip()
@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,

    },
)
def test_tcp_socket_max_psp(wifi_sniffer, wifi_associated_dut_with_sniffer, rf_attenuator, utf_constants):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 10
    count_disconnect, count_connect, count_rejoin = set(), set(), set()
    try:
        if isinstance(wifi_associated_dut_with_sniffer.interfaces.wifi, RSSAPICommands):
            wifi_associated_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)

            ip_result = wifi_associated_dut_with_sniffer.interfaces.wifi.start_ip()
            dut_ip = ip_result.ip.decode()
            logger().info(f"DUT ip address: {dut_ip}")

            """Applying Max power save """
            logger().info(f"*****Enable Max PSP in DUT******")
            wifi_associated_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
            wifi_associated_dut_with_sniffer.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            ap_ssid = wifi_associated_dut_with_sniffer.interfaces.wifi.ssid
            logger().info(f"AP_ssid {ap_ssid}")

            test_execution_time = utf_constants.get("time_duration")
            logger().info(f'\n\n ***** Time duration = {test_execution_time}\n\n')

            tcp_socket_id = tcp_socket_obj.open_socket(wifi_associated_dut_with_sniffer, dut_ip)
            connect_status = tcp_socket_obj.connect_socket(wifi_associated_dut_with_sniffer, tcp_socket_id)
            if connect_status is False:
                logger().info("Unable to connect with Server")
                assert connect_status

            """ Start time for long duration and send messages """
            end_time = datetime.now() + timedelta(hours=test_execution_time)
            start_time = datetime.now()

            while 1:
                if datetime.now() >= end_time:
                    close_response = wifi_associated_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                    logger().info(f"close_response: {close_response}")
                    break
                logger().info(datetime.now())
                send_response = wifi_associated_dut_with_sniffer.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                        time.sleep(55)

                events = wifi_associated_dut_with_sniffer.interfaces.wifi.get_async_events()
                connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
                disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
                rejoin_error_events = [event for event in events if
                                       event.event_type == RS9116AsyncEventType.RejoinError]
                if len(disconnect_events):
                    count_disconnect.add(str(disconnect_events[0]))
                if len(connect_events):
                    count_connect.add(str(connect_events[0]))
                if len(rejoin_error_events):
                    count_rejoin.add(str(rejoin_error_events[0]))

                """Validate connection when DUT disconnected from AP """
                if (datetime.now() < end_time) and len(disconnect_events):
                    logger().info('Validate connection when DUT disconnected from AP')
                    if len(disconnect_events):
                        count_disconnect.add(str(disconnect_events[0]))
                        logger().info(f' Disconnect Event = {count_disconnect}')
                    time.sleep(130)
                    events = wifi_associated_dut_with_sniffer.interfaces.wifi.get_async_events()
                    connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
                    if len(connect_events):
                        count_connect.add(str(connect_events[0]))
                        close_response = wifi_associated_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                        logger().info(f"close_response: {close_response}")
                        tcp_socket_id = tcp_socket_obj.open_socket(wifi_associated_dut_with_sniffer, dut_ip)
                        time.sleep(2)
                        tcp_socket_obj.connect_socket(wifi_associated_dut_with_sniffer, tcp_socket_id)
                    else:
                        logger().info("Unable to connect with AP after 130 seconds")
                        break
                elif 'status -1' in str(send_response):
                    logger().info("If Socket disconnected from server")
                    tcp_socket_obj.connect_socket(wifi_associated_dut_with_sniffer, tcp_socket_id)

    except (IndexError, CLITransportException, AssertionError):
        logger().info("Find exception")
        assert False

    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

        """Verification of connect or disconnect event"""
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
        rejoin_error_events = [event for event in events if event.event_type == RS9116AsyncEventType.RejoinError]
        if len(disconnect_events): count_disconnect.add(str(disconnect_events[0]))
        if len(connect_events): count_connect.add(str(connect_events[0]))
        if len(rejoin_error_events): count_rejoin.add(str(rejoin_error_events[0]))
        if count_connect: logger().info(f'Total no of connection={len(count_connect)}')
        if count_disconnect: logger().info(f'Total no of disconnect={len(count_disconnect)}')
        if count_rejoin: logger().info(f'Total no of Rejoin={len(count_rejoin)}')
        end_time = datetime.now()
        exact_execution_time = end_time - start_time
        logger().info(f"Total execution time of test case = {exact_execution_time}")


#Feature enhancement to be done..
pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("static_ap"),
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
            "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
                OpenMode | RS9116FeatureBitMap.PSKSecurity,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
                EnahanceMaxPsp,
            "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        },
    ),
]
@pytest.mark.skip
@pytest.mark.start_state("rf_attenuator", device='50pa500_attenuator')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_enhanced_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, aws_iot_dut, rf_attenuator, utf_constants):
    topic_1 = "IOP_AWS_Shadow"

    """ Start time for long duration and send messages """
    test_execution_time = utf_constants.get("time_duration")
    logger().info(f'\n\n ***** Time duration = {test_execution_time}\n\n')
    end_time = datetime.now() + timedelta(hours=test_execution_time)
    start_time = datetime.now()
    try:
        wifi_networked_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)
        aws_iot_dut.interfaces.aws_iot.aws_iot_connect()
        time.sleep(2)

        """Applying Max power save """
        logger().info(f"*****Enable Enhanced Max Power save in DUT******")
        wifi_networked_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 1)

        shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
            RS9116AsyncEventType.AWSIoTMQTTMessage
        ]
        time.sleep(2)
        aws_iot_dut.interfaces.aws_iot.aws_iot_subscribe(topic_1, 0)
        time.sleep(4)
        while 1:
            if datetime.now() >= end_time:
                aws_iot_dut.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
                time.sleep(2)
                aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
                break
            aws_iot_dut.interfaces.aws_iot.aws_iot_publish(
                topic_1, '{"message": "Message from RS9611"}', 0
            )
            shadow_update_accepted_event_queue.get(timeout=10)
            time.sleep(55)

    except (QueueEmpty, Empty):
        assert False, "Did not receive an expected shadow update accepted event"
    finally:
        end_time = datetime.now()
        exact_execution_time = end_time - start_time
        logger().info(f"Total execution time of test case = {exact_execution_time}")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")


pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("static_ap"),
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
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        },
    ),
]


@pytest.mark.skip
@pytest.mark.start_state("rf_attenuator", device='50pa500_attenuator')
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, aws_iot_dut, rf_attenuator, utf_constants):
    topic_1 = "IOP_AWS_Shadow"

    """ Start time for long duration and send messages """
    test_execution_time = utf_constants.get("time_duration")
    logger().info(f'\n\n ***** Time duration = {test_execution_time}\n\n')

    end_time = datetime.now() + timedelta(hours=test_execution_time)
    start_time = datetime.now()
    try:
        wifi_networked_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)
        aws_iot_dut.interfaces.aws_iot.aws_iot_connect()
        time.sleep(2)

        """Applying Max power save """
        logger().info(f"*****Enable Enhanced Max Power save in DUT******")
        wifi_networked_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 0)
        wifi_networked_dut_with_sniffer.interfaces.wifi.bt_power_save(
            power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )

        shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
            RS9116AsyncEventType.AWSIoTMQTTMessage
        ]
        time.sleep(2)
        aws_iot_dut.interfaces.aws_iot.aws_iot_subscribe(topic_1, 0)
        time.sleep(4)
        while 1:
            if datetime.now() >= end_time:
                aws_iot_dut.interfaces.aws_iot.aws_iot_unsubscribe(topic_1)
                time.sleep(2)
                aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
                break
            aws_iot_dut.interfaces.aws_iot.aws_iot_publish(
                topic_1, '{"message": "Message from RS9611"}', 0
            )
            shadow_update_accepted_event_queue.get(timeout=10)
            time.sleep(55)

    except (QueueEmpty, Empty):
        assert False, "Did not receive an expected shadow update accepted event"
    finally:
        end_time = datetime.now()
        exact_execution_time = end_time - start_time
        logger().info(f"Total execution time of test case = {exact_execution_time}")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")


pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("static_ap"),
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.firmware_app("test_aws"),
    pytest.mark.start_state("rf_attenuator", device='50pa500_attenuator'),
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
            "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
                OpenMode | RS9116FeatureBitMap.PSKSecurity,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
                EnahanceMaxPsp,
            "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
            "ca_cert": ["start_field.pem"],
            "client_cert": ["client-certificate.crt"],
            "client_key": ["private-key.key"],
        },
    ),
]


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_device_shadow_enhanced_max_psp_c34033(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, aws_iot_dut,
                                            rf_attenuator, utf_constants, request):
    rejected_event_counter = 0
    timeout_event_counter = 0
    test_name = request.node.name
    disconnect_packet_list = []

    """ Start time for long duration and send messages """
    test_execution_time = utf_constants.get("time_duration")
    logger().info(f'\n\n ***** Time duration = {test_execution_time}\n\n')

    end_time = datetime.now() + timedelta(hours=test_execution_time)
    start_time = datetime.now()
    try:
        with wifi_sniffer.interfaces.live_capture as live_capture:
            live_capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            live_capture.start_live_capture(timeout=end_time, capture_file=test_name, filter_layer_name='wlan',
                                            filter_field='wlan.fc.type_subtype', filter_val='12')

            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {mac_address}")

            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator)
            logger().info("Initiating aws connect from DUT")
            assert connect_aws_server_from_dut(aws_iot_dut), "Failed to connect aws server from DUT"
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)
            """Applying enhanced max psp power save """
            logger().info(f"*****Enable Enhanced Max Power save in DUT******")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave
                                                   )

            shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
                RS9116AsyncEventType.AWSIoTShadowUpdateAccepted
            ]
            shadow_update_rejected_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
                RS9116AsyncEventType.AWSIoTShadowUpdateRejected
            ]
            shadow_update_timeout_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
                RS9116AsyncEventType.AWSIoTShadowUpdateTimeout
            ]
            is_packet_found = False
            while datetime.now() < end_time:
                aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_update(random.randint(1, 100))
                try:
                    shadow_update_accepted_event_queue.get(timeout=60)
                except(QueueEmpty, Empty):
                    # did not receive update accepted event
                    pass
                try:
                    shadow_update_rejected_event_queue.get(timeout=60)
                    rejected_event_counter = rejected_event_counter + 1
                except(QueueEmpty, Empty):
                    # did not receive rejected event
                    pass
                try:
                    shadow_update_timeout_event_queue.get(timeout=60)
                    timeout_event_counter = timeout_event_counter + 1
                except(QueueEmpty, Empty):
                    # did not receive timeout event
                    pass
                packet = live_capture.get_packet()
                if packet is not None:
                    is_packet_found = True
                    disconnect_packet_list.append(packet)
                    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            live_capture.stop_live_capture()
            logger().info("\n\n **** Stop Sniffer finally **** \n\n")
            if is_packet_found:
                logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
                logger().info("\n\n **** Disconnected packet list ****\n\n")
                logger().info(disconnect_packet_list)
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    finally:
        time.sleep(55)
        wifi_dut.interfaces.wifi.leave()
        aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
        logger().info("AWS server disconnection from DUT")
        end_time = datetime.now()
        exact_execution_time = end_time - start_time
        logger().info(f"\n\n Total execution time of test case = {exact_execution_time}\n\n")
        logger().info(f"\n\n Total number of Rejected Event Counter = {rejected_event_counter}\n\n")
        logger().info(f"\n\n Total number of Timeout Event Counter = {timeout_event_counter}\n\n")


pytestmark = [
    pytest.mark.framework_integration_test,
    pytest.mark.wifi_access_point("static_ap"),
    pytest.mark.dut("rs9116_sapi"),
    pytest.mark.firmware_app("test_aws"),
    pytest.mark.start_state("rf_attenuator", device='50pa500_attenuator'),
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
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.Default | RS9116FeatureBitMap.ULPGPIOHandshake,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
            "ca_cert": ["start_field.pem"],
            "client_cert": ["client-certificate.crt"],
            "client_key": ["private-key.key"],
        },
    ),
]


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_aws_device_shadow_max_psp_c34082(firmware_loader, wifi_dut, wifi_access_point, wifi_sniffer, aws_iot_dut,
                                            rf_attenuator, utf_constants, request):
    rejected_event_counter = 0
    timeout_event_counter = 0
    test_name = request.node.name
    disconnect_packet_list = []

    """ Start time for long duration and send messages """
    test_execution_time = utf_constants.get("time_duration")
    logger().info(f'\n\n ***** Time duration = {test_execution_time}\n\n')

    end_time = datetime.now() + timedelta(hours=test_execution_time)
    start_time = datetime.now()
    try:
        with wifi_sniffer.interfaces.live_capture as live_capture:
            live_capture.configure_interface(
                channel=wifi_access_point.interfaces.wifi.channel
            )
            live_capture.start_live_capture(timeout=end_time, capture_file=test_name, filter_layer_name='wlan',
                                            filter_field='wlan.fc.type_subtype', filter_val='12')

            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {mac_address}")

            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator)
            logger().info("Initiating aws connect from DUT")
            assert connect_aws_server_from_dut(aws_iot_dut), "Failed to connect aws server from DUT"
            logger.info("Connecting to AWS server from DUT is successful")
            time.sleep(2)

            """Applying max psp power save """
            logger().info(f"*****Enable Max Power save in DUT******")
            wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.MaxPowerSave)
            wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.MaxPowerSave
                                                   )
            shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
                RS9116AsyncEventType.AWSIoTShadowUpdateAccepted
            ]
            shadow_update_rejected_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
                RS9116AsyncEventType.AWSIoTShadowUpdateRejected
            ]
            shadow_update_timeout_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
                RS9116AsyncEventType.AWSIoTShadowUpdateTimeout
            ]
            is_packet_found = False
            while datetime.now() < end_time:
                aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_update(random.randint(1, 100))
                try:
                    shadow_update_accepted_event_queue.get(timeout=60)
                except(QueueEmpty, Empty):
                    # did not receive update accepted event
                    pass
                try:
                    shadow_update_rejected_event_queue.get(timeout=60)
                    rejected_event_counter = rejected_event_counter + 1
                except(QueueEmpty, Empty):
                    # did not receive rejected event
                    pass
                try:
                    shadow_update_timeout_event_queue.get(timeout=60)
                    timeout_event_counter = timeout_event_counter + 1
                except(QueueEmpty, Empty):
                    # did not receive timeout event
                    pass
                packet = live_capture.get_packet()
                if packet is not None:
                    is_packet_found = True
                    disconnect_packet_list.append(packet)
                    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            live_capture.stop_live_capture()
            logger().info("\n\n **** Stop Sniffer finally **** \n\n")
            if is_packet_found:
                logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
                logger().info("\n\n **** Disconnected packet list ****\n\n")
                logger().info(disconnect_packet_list)
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    finally:
        time.sleep(55)
        wifi_dut.interfaces.wifi.leave()
        aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
        logger().info("AWS server disconnection from DUT")
        end_time = datetime.now()
        exact_execution_time = end_time - start_time
        logger().info(f"\n\n Total execution time of test case = {exact_execution_time}\n\n")
        logger().info(f"\n\n Total number of Rejected Event Counter = {rejected_event_counter}\n\n")
        logger().info(f"\n\n Total number of Timeout Event Counter = {timeout_event_counter}\n\n")