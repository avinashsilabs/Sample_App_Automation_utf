import random
import re
import time
from _queue import Empty
from asyncio import QueueEmpty
from datetime import datetime, timedelta

from utf.interfaces.cli import CLITransportException
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes
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
"""


class IopTcpIpSockets:
    def open_socket(self, wifi_networked_dut) -> int:
        if isinstance(wifi_networked_dut.interfaces.wifi, RSSAPICommands):
            result = wifi_networked_dut.interfaces.wifi.start_ip()
            dut_ip = result.ip.decode()
            logger().info(f"DUT ip address : {dut_ip}")
            assert isinstance(result, wifi_networked_dut.interfaces.wifi.IPConfig)

            tcp_socket_id = wifi_networked_dut.interfaces.wifi.open_tcp_client_socket()
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)

            time.sleep(2)
            bind_response = wifi_networked_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip)
            if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
                logger().info(f"Bind socket successfully: {bind_response}")
            else:
                logger().error(f"Unable to bind socket: {bind_response}")
                raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_networked_dut, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_networked_dut.interfaces.wifi.connect(tcp_socket_id)
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


@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
            EnahanceMaxPsp,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    },
)
def test_tcp_socket_enhanced_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, rf_attenuator):

    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 10
    count_disconnect, count_connect, count_rejoin = set(), set(), set()
    try:
        if isinstance(wifi_networked_dut_with_sniffer.interfaces.wifi, RSSAPICommands):
            wifi_networked_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)

            """Applying Max power save """
            logger().info(f"*****Enable Enhanced Max Power save in DUT******")
            wifi_networked_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 1)
            ap_ssid = wifi_networked_dut_with_sniffer.interfaces.wifi.ssid
            logger().info(f"AP_ssid {ap_ssid}")

            tcp_socket_id = tcp_socket_obj.open_socket(wifi_networked_dut_with_sniffer)
            time.sleep(5)
            connect_status = tcp_socket_obj.connect_socket(wifi_networked_dut_with_sniffer, tcp_socket_id)
            if connect_status is False:
                logger().info("Unable to connect with Server")
                assert connect_status

            """ Start time for long duration and send messages """
            end_time = datetime.now() + timedelta(hours=12)
            start_time = datetime.now()

            while 1:
                if datetime.now() >= end_time:
                    close_response = wifi_networked_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                    logger().info(f"close_response: {close_response}")
                    break
                logger().info(datetime.now())
                send_response = wifi_networked_dut_with_sniffer.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                        time.sleep(55)

                events = wifi_networked_dut_with_sniffer.interfaces.wifi.get_async_events()
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
                    events = wifi_networked_dut_with_sniffer.interfaces.wifi.get_async_events()
                    connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
                    if len(connect_events):
                        count_connect.add(str(connect_events[0]))
                        close_response = wifi_networked_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                        logger().info(f"close_response: {close_response}")
                        tcp_socket_id = tcp_socket_obj.open_socket(wifi_networked_dut_with_sniffer)
                        time.sleep(2)
                        tcp_socket_obj.connect_socket(wifi_networked_dut_with_sniffer, tcp_socket_id)
                    else:
                        logger().info("Unable to connect with AP after 130 seconds")
                        break
                elif 'status -1' in str(send_response):
                    logger().info("If Socket disconnected from server")
                    tcp_socket_obj.connect_socket(wifi_networked_dut_with_sniffer, tcp_socket_id)

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
    wifi_networked_dut_with_sniffer.interfaces.wifi.leave()


@pytest.mark.rf_attenuator('50pa500_attenuator')
@pytest.mark.start_state("wifi_dut", device="reset", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
def test_tcp_socket_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, rf_attenuator):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 10
    count_disconnect, count_connect, count_rejoin = set(), set(), set()
    try:
        if isinstance(wifi_networked_dut_with_sniffer.interfaces.wifi, RSSAPICommands):
            wifi_networked_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)

            """Applying Max power save """
            logger().info(f"*****Enable Max PSP in DUT******")
            wifi_networked_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 0)
            wifi_networked_dut_with_sniffer.interfaces.wifi.bt_power_save(
                power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
            )
            ap_ssid = wifi_networked_dut_with_sniffer.interfaces.wifi.ssid
            logger().info(f"AP_ssid {ap_ssid}")

            tcp_socket_id = tcp_socket_obj.open_socket(wifi_networked_dut_with_sniffer)
            connect_status = tcp_socket_obj.connect_socket(wifi_networked_dut_with_sniffer, tcp_socket_id)
            if connect_status is False:
                logger().info("Unable to connect with Server")
                assert connect_status

            """ Start time for long duration and send messages """
            end_time = datetime.now() + timedelta(hours=12)
            start_time = datetime.now()

            while 1:
                if datetime.now() >= end_time:
                    close_response = wifi_networked_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                    logger().info(f"close_response: {close_response}")
                    break
                logger().info(datetime.now())
                send_response = wifi_networked_dut_with_sniffer.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                        time.sleep(55)

                events = wifi_networked_dut_with_sniffer.interfaces.wifi.get_async_events()
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
                    events = wifi_networked_dut_with_sniffer.interfaces.wifi.get_async_events()
                    connect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Connect]
                    if len(connect_events):
                        count_connect.add(str(connect_events[0]))
                        close_response = wifi_networked_dut_with_sniffer.interfaces.wifi.close_socket(tcp_socket_id)
                        logger().info(f"close_response: {close_response}")
                        tcp_socket_id = tcp_socket_obj.open_socket(wifi_networked_dut_with_sniffer)
                        time.sleep(2)
                        tcp_socket_obj.connect_socket(wifi_networked_dut_with_sniffer, tcp_socket_id)
                    else:
                        logger().info("Unable to connect with AP after 130 seconds")
                        break
                elif 'status -1' in str(send_response):
                    logger().info("If Socket disconnected from server")
                    tcp_socket_obj.connect_socket(wifi_networked_dut_with_sniffer, tcp_socket_id)

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


@pytest.mark.rf_attenuator('50pa500_attenuator')
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


def test_aws_enhanced_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, aws_iot_dut, rf_attenuator):
    topic_1 = "IOP_AWS_Shadow"

    """ Start time for long duration and send messages """
    end_time = datetime.now() + timedelta(hours=12)
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


@pytest.mark.rf_attenuator('50pa500_attenuator')
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
def test_aws_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, aws_iot_dut, rf_attenuator):
    topic_1 = "IOP_AWS_Shadow"

    """ Start time for long duration and send messages """
    end_time = datetime.now() + timedelta(hours=12)
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


@pytest.mark.rf_attenuator('50pa500_attenuator')
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
def test_aws_device_shadow_enhanced_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, aws_iot_dut, rf_attenuator):
    rejected_event_counter = 0
    timeout_event_counter = 0
    """ Start time for long duration and send messages """
    end_time = datetime.now() + timedelta(hours=12)
    start_time = datetime.now()
    wifi_networked_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)
    aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_init()
    time.sleep(2)
    """Applying Max power save """
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    wifi_networked_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 1)

    shadow_update_accepted_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateAccepted
    ]
    shadow_update_rejected_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateRejected
    ]
    shadow_update_timeout_event_queue = aws_iot_dut.interfaces.aws_iot.event_queues[
        RS9116AsyncEventType.AWSIoTShadowUpdateTimeout
    ]
    while datetime.now() < end_time:
        aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_update(random.randint(1,100))
        try:
            shadow_update_accepted_event_queue.get(timeout=10)
        except(QueueEmpty, Empty):
            # did not receive update accepted event
            pass
        try:
            shadow_update_rejected_event_queue.get(timeout=10)
            rejected_event_counter = rejected_event_counter + 1
        except(QueueEmpty, Empty):
            # did not receive rejected event
            pass
        try:
            shadow_update_timeout_event_queue.get(timeout=10)
            timeout_event_counter = timeout_event_counter + 1
        except(QueueEmpty, Empty):
            # did not receive timeout event
            pass
    time.sleep(55)
    aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
    logger().info("AWS server disconnection from DUT")
    end_time = datetime.now()
    exact_execution_time = end_time - start_time
    logger().info(f"Total execution time of test case = {exact_execution_time}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"Total number of Rejected Event Counter = {rejected_event_counter}")
    logger().info(f"Total number of Timeout Event Counter = {timeout_event_counter}")


@pytest.mark.rf_attenuator('50pa500_attenuator')
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
def test_aws_device_shadow_max_psp(wifi_sniffer, wifi_networked_dut_with_sniffer, aws_iot_dut, rf_attenuator):
    rejected_event_counter = 0
    timeout_event_counter = 0
    """ Start time for long duration and send messages """
    end_time = datetime.now() + timedelta(hours=12)
    start_time = datetime.now()
    wifi_networked_dut_with_sniffer.interfaces.wifi.set_attenuator(rf_attenuator)
    aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_init()
    time.sleep(2)
    """Applying Max power save """
    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    wifi_networked_dut_with_sniffer.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2, 0)
    wifi_networked_dut_with_sniffer.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
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
    while datetime.now() < end_time:
        aws_iot_dut.interfaces.aws_iot.aws_iot_shadow_update(random.randint(1,100))
        try:
            shadow_update_accepted_event_queue.get(timeout=10)
        except(QueueEmpty, Empty):
            # did not receive update accepted event
            pass
        try:
            shadow_update_rejected_event_queue.get(timeout=10)
            rejected_event_counter = rejected_event_counter + 1
        except(QueueEmpty, Empty):
            # did not receive rejected event
            pass
        try:
            shadow_update_timeout_event_queue.get(timeout=10)
            timeout_event_counter = timeout_event_counter + 1
        except(QueueEmpty, Empty):
            # did not receive timeout event
            pass
    time.sleep(55)
    aws_iot_dut.interfaces.aws_iot.aws_iot_disconnect()
    logger().info("AWS server disconnection from DUT")
    end_time = datetime.now()
    exact_execution_time = end_time - start_time
    logger().info(f"Total execution time of test case = {exact_execution_time}")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    logger().info(f"Total number of Rejected Event Counter = {rejected_event_counter}")
    logger().info(f"Total number of Timeout Event Counter = {timeout_event_counter}")