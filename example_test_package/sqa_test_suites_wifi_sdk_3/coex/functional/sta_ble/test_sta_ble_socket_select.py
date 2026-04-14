import time
import pytest
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xMqttQos
)
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, WifiJoinThread, cleanup_ble
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
import random
import string
from random import randint
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers



def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. scan ,connect, data transfer
        6. ble connection slave/master
        7. check socket select functionality 

    Author: Swathi.Chinthala

"""


class SocketDataTransfer:

    @staticmethod
    def close_socket(wifi_dut, socket_id, remote_socket):
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=socket_id)
        logger().info(f"Successfully closed socket_id '{socket_id}' in the DUT")
        remote_socket.interfaces.socket.stop()

    @staticmethod
    def send_data(remote_socket, tx_buffer, pkt_count=10, sock_id=None, use_server=True):
        for _ in range(pkt_count):
            if sock_id is None:
                remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server)
            else:
                remote_socket.interfaces.socket.sockets[sock_id].send_data_tcp(tx_buffer, use_server)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(0)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133576')
def test_Coex_sdk_WLAN_TCP_socket_select_without_bit_BLE_scan_C133576(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Scan from DUT device and connect to REMOTE
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors, waiting until one of the file descriptors becomes active
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()

        wifi_dut.interfaces.wifi.set_filter_broadcast()
        server_port = random.randint(5001, 5020)
        local_port = random.randint(40001, 60000)
        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)

        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=local_port, timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)
        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        buffer_length = len(tx_buffer)
        remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)


        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1,
                                                 time=30, timeout=30, expected_status=SLStatus.SL_STATUS_FAIL)

        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133577')
def test_Coex_sdk_WLAN_TCP_socket_select_when_no_socket_BLE_scan_C133577(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Scan from DUT device and connect to REMOTE
        6. Enable wlan and bt power save mode in dut after the connection
        7. Give socket select command without opening any socket
        8. DUT should give 0x07 error
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        status = ping(wifi_obj.device_ip, 10, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        wifi_dut.interfaces.wifi.set_filter_broadcast()
        try:
            status, data = wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=2,
                                                 time=30, timeout=30, expected_status=SLStatus.SL_STATUS_FAIL)
            logger().info(f"status: {status}, data: {data}")
            assert "errno: 9" in data.decode("utf-8"), f"expected error 9 but received {data.decode('utf-8')}"
            logger().info("socket select failed with bsd errno: 9")
        except Exception as Ex:
            logger().info(f"EXCEPTION OCCURRED:{Ex}")
            wifi_dut.interfaces.wifi.get_saved_firmware_status()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133578')
def test_Coex_sdk_WLAN_TCP_socket_select_rx_BLE_master_C133578(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Scan from DUT device and connect to REMOTE
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_dut_addr = ble_obj.ble_dut_address
        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"], server_port=port, timeout=30, asynch=0)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=0)

        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))

            logger().info(f"tx_buffer: {tx_buffer}")
            buffer_length = len(tx_buffer)

            logger().info(f"count : {count}")

            if count == 0:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 0),
                        (
                            client_socket.connect_client_tcp,
                            wifi_obj.dut_addr["device_ip"],
                            port,
                        ),
                    ],
                    timeout=10,
                )
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketSelect, 1, 30),
                        (
                            client_socket.send_data_tcp,
                            tx_buffer,
                        ),
                    ],
                    timeout=10,
                )
            time.sleep(1)
            client_socket.send_data_tcp(tx_buffer)

            for retry in range(3):
                try:
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
                    break
                except:
                    logger().info(f"retrying to receive data from the socket id {sock} opened in the DUT")
                    if retry == 2:
                        raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")

            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"
            count = count + 1
        time.sleep(1)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133579')
def test_Coex_sdk_WLAN_TCP_socket_select_rx_BLE_scann_C133579(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"], server_port=port,
                                      timeout=30, asynch=0)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=0)

        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))

            logger().info(f"tx_buffer: {tx_buffer}")
            buffer_length = len(tx_buffer)

            logger().info(f"count : {count}")

            if count == 0:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 0),
                        (
                            client_socket.connect_client_tcp,
                            wifi_obj.dut_addr["device_ip"],
                            port,
                        ),
                    ],
                    timeout=10,
                )
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketSelect, 1, 30),
                        (
                            client_socket.send_data_tcp,
                            tx_buffer,
                        ),
                    ],
                    timeout=10,
                )
            time.sleep(1)
            client_socket.send_data_tcp(tx_buffer)

            for retry in range(3):
                try:
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
                    break
                except:
                    logger().info(f"retrying to receive data from the socket id {sock} opened in the DUT")
                    if retry == 2:
                        raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")

            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"
            time.sleep(1)
            count = count + 1
        time.sleep(2)
        ble_obj.stop_scan_adv()
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133580')
def test_Coex_sdk_WLAN_TCP_async_socket_select_rx_BLE_scann_C133580(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using async select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """

    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"], server_port=port,
                                      timeout=30, asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))

            logger().info(f"tx_buffer: {tx_buffer}")
            buffer_length = len(tx_buffer)

            logger().info(f"count : {count}")

            if count == 0:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                        (
                            client_socket.connect_client_tcp,
                            wifi_obj.dut_addr["device_ip"],
                            port,
                        ),
                    ],
                    timeout=10,
                )
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdAsyncSocketSelect, 1, 30),
                        (
                            client_socket.send_data_tcp,
                            tx_buffer,
                        ),
                    ],
                    timeout=10,
                )
            time.sleep(1)
            client_socket.send_data_tcp(tx_buffer)

            for retry in range(3):
                try:
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
                    break
                except:
                    logger().info(f"retrying to receive data from the socket id {sock} opened in the DUT")
                    if retry == 2:
                        raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")

            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"
            count = count + 1
            time.sleep(2)
        ble_obj.stop_scan_adv()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133581')
def test_Coex_sdk_WLAN_TCP_sync_socket_select_threads_BLE_scann_C133581(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create 4 TCP sockets,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with multiple socket descriptors
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"],
                                          server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, wifi_obj.dut_addr["device_ip"], server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
        time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        logger().info(f"tcp_socks:{tcp_socks}")
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
                logger().info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                client_socket[count].connected_tcp_socket = client_socket[count]
                client_socket[count].send_data_tcp(tx_buffer)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock_no) + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger().info(f"Data received at DUT --> {buffer_rx}")
                logger().info("Data sent by remote peer and received on DUT is matching")
                count += 1
        time.sleep(3)
        ble_obj.stop_scan_adv()
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
            time.sleep(1)

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        tcp_socks.clear()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C133582')
def test_Coex_sdk_socket_select_remote_terminate_BLE_scan_C133582(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """

    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        wifi_dut.interfaces.wifi.set_remote_terminate_callback()

        local_port = randint(6000, 6100)
        logger().info("Starting TCP Server socket at remote device")

        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"],
                                      server_port=local_port, asynch=0)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=0)

        tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
        buffer_length = len(tx_buffer)


        result = ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 0),
                (
                    remote_socket.interfaces.socket.connect_client_tcp,
                    wifi_obj.dut_addr["device_ip"],
                    local_port,
                ),
            ],
            timeout=10,
        )
        result = ThreadBase.call_functions_simultaneously(
            [
                (wifi_dut.interfaces.wifi.bsdSocketSelect, 1, 30),
                (
                    remote_socket.interfaces.socket.send_data_tcp,
                    tx_buffer,
                ),
            ],
            timeout=10,)

        buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)

        sw = Stopwatch()
        while sw.elapsed_sec < 10:
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer)
            time.sleep(2)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
            logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
            logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched "

        time.sleep(2)
        remote_socket.interfaces.socket.stop()
        for i in range(0, 3):
            time.sleep(5)
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events) >= 1:
                break
        assert len(events) >= 1, "TCP Remote terminate event not found"

        remote_terminate = ""
        for event in events:
            if (event.event_type == AsyncEventIdentifiers.REMOTE_TERMINATE) or ("Remote Terminate" in event.event_data):
                remote_terminate = event.event_data
        logger().info(f"*********{remote_terminate}*************")
        assert remote_terminate, f"unable to find remote terminate event"
        logger().info("Remote terminate event is received by DUT when tcp socket connected is closed")

        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780394')
def test_Coex_sdk_WLAN_TCP_socket_select_when_no_socket_BLE_scan_SI_60ms_SW_20ms_C780394(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Scan from DUT device and connect to REMOTE
        6. Enable wlan and bt power save mode in dut after the connection
        7. Give socket select command without opening any socket
        8. DUT should give 0x07 error
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=60,
            scan_window=20
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        status = ping(wifi_obj.device_ip, 10, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        wifi_dut.interfaces.wifi.set_filter_broadcast()
        try:
            status, data = wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=2,
                                                 time=30, timeout=30, expected_status=SLStatus.SL_STATUS_FAIL)
            logger().info(f"status: {status}, data: {data}")
            assert "errno: 9" in data.decode("utf-8"), f"expected error 9 but received {data.decode('utf-8')}"
            logger().info("socket select failed with bsd errno: 9")
        except Exception as Ex:
            logger().info(f"EXCEPTION OCCURRED:{Ex}")
            wifi_dut.interfaces.wifi.get_saved_firmware_status()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780395')
def test_Coex_sdk_WLAN_TCP_socket_select_when_no_socket_BLE_scan_SI_300ms_SW_100ms_C780395(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Scan from DUT device and connect to REMOTE
        6. Enable wlan and bt power save mode in dut after the connection
        7. Give socket select command without opening any socket
        8. DUT should give 0x07 error
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=300,
            scan_window=100
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        status = ping(wifi_obj.device_ip, 10, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        wifi_dut.interfaces.wifi.set_filter_broadcast()
        try:
            status, data = wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=2,
                                                 time=30, timeout=30, expected_status=SLStatus.SL_STATUS_FAIL)
            logger().info(f"status: {status}, data: {data}")
            assert "errno: 9" in data.decode("utf-8"), f"expected error 9 but received {data.decode('utf-8')}"
            logger().info("socket select failed with bsd errno: 9")
        except Exception as Ex:
            logger().info(f"EXCEPTION OCCURRED:{Ex}")
            wifi_dut.interfaces.wifi.get_saved_firmware_status()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780396')
def test_Coex_sdk_WLAN_TCP_socket_select_when_no_socket_BLE_scan_SI_900ms_SW_300ms_C780396(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Scan from DUT device and connect to REMOTE
        6. Enable wlan and bt power save mode in dut after the connection
        7. Give socket select command without opening any socket
        8. DUT should give 0x07 error
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=900,
            scan_window=300
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        status = ping(wifi_obj.device_ip, 10, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        wifi_dut.interfaces.wifi.set_filter_broadcast()
        try:
            status, data = wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=2,
                                                 time=30, timeout=30, expected_status=SLStatus.SL_STATUS_FAIL)
            logger().info(f"status: {status}, data: {data}")
            assert "errno: 9" in data.decode("utf-8"), f"expected error 9 but received {data.decode('utf-8')}"
            logger().info("socket select failed with bsd errno: 9")
        except Exception as Ex:
            logger().info(f"EXCEPTION OCCURRED:{Ex}")
            wifi_dut.interfaces.wifi.get_saved_firmware_status()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780397')
def test_Coex_sdk_WLAN_TCP_async_socket_select_rx_BLE_scan_SI_60ms_SW_20ms_C780397(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using async select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """

    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=60,
            scan_window=20
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"], server_port=port,
                                      timeout=30, asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))

            logger().info(f"tx_buffer: {tx_buffer}")
            buffer_length = len(tx_buffer)

            logger().info(f"count : {count}")

            if count == 0:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                        (
                            client_socket.connect_client_tcp,
                            wifi_obj.dut_addr["device_ip"],
                            port,
                        ),
                    ],
                    timeout=10,
                )
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdAsyncSocketSelect, 1, 30),
                        (
                            client_socket.send_data_tcp,
                            tx_buffer,
                        ),
                    ],
                    timeout=10,
                )
            time.sleep(1)
            client_socket.send_data_tcp(tx_buffer)

            for retry in range(3):
                try:
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
                    break
                except:
                    logger().info(f"retrying to receive data from the socket id {sock} opened in the DUT")
                    if retry == 2:
                        raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")

            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"
            count = count + 1
            time.sleep(2)
        ble_obj.stop_scan_adv()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780398')
def test_Coex_sdk_WLAN_TCP_async_socket_select_rx_BLE_scan_SI_300ms_SW_100ms_C780398(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using async select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """

    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=300,
            scan_window=100
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"], server_port=port,
                                      timeout=30, asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))

            logger().info(f"tx_buffer: {tx_buffer}")
            buffer_length = len(tx_buffer)

            logger().info(f"count : {count}")

            if count == 0:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                        (
                            client_socket.connect_client_tcp,
                            wifi_obj.dut_addr["device_ip"],
                            port,
                        ),
                    ],
                    timeout=10,
                )
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdAsyncSocketSelect, 1, 30),
                        (
                            client_socket.send_data_tcp,
                            tx_buffer,
                        ),
                    ],
                    timeout=10,
                )
            time.sleep(1)
            client_socket.send_data_tcp(tx_buffer)

            for retry in range(3):
                try:
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
                    break
                except:
                    logger().info(f"retrying to receive data from the socket id {sock} opened in the DUT")
                    if retry == 2:
                        raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")

            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"
            count = count + 1
            time.sleep(2)
        ble_obj.stop_scan_adv()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
                                   | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
        },
    },
)

@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780399')
def test_Coex_sdk_WLAN_TCP_async_socket_select_rx_BLE_scan_SI_900ms_SW_300ms_C780399(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create TCP socket,Choose socket using async select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """

    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=900,
            scan_window=300
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        port = random.randint(5001, 5020)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()
        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"], server_port=port,
                                      timeout=30, asynch=1)
        wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=1, asynch=1)

        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:

            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))

            logger().info(f"tx_buffer: {tx_buffer}")
            buffer_length = len(tx_buffer)

            logger().info(f"count : {count}")

            if count == 0:
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1),
                        (
                            client_socket.connect_client_tcp,
                            wifi_obj.dut_addr["device_ip"],
                            port,
                        ),
                    ],
                    timeout=10,
                )
                result = ThreadBase.call_functions_simultaneously(
                    [
                        (wifi_dut.interfaces.wifi.bsdAsyncSocketSelect, 1, 30),
                        (
                            client_socket.send_data_tcp,
                            tx_buffer,
                        ),
                    ],
                    timeout=10,
                )
            time.sleep(1)
            client_socket.send_data_tcp(tx_buffer)

            for retry in range(3):
                try:
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock) + 1, timeout=30)
                    break
                except:
                    logger().info(f"retrying to receive data from the socket id {sock} opened in the DUT")
                    if retry == 2:
                        raise Exception(f"failed to receive data from the socket id {sock} opened in the DUT")

            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"
            count = count + 1
            time.sleep(2)
        ble_obj.stop_scan_adv()
        wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780400')
def test_Coex_sdk_WLAN_TCP_sync_socket_select_threads_BLE_scan_SI_60ms_SW_20ms_C780400(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create 4 TCP sockets,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with multiple socket descriptors
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=60,
            scan_window=20
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"],
                                          server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, wifi_obj.dut_addr["device_ip"], server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
        time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        logger().info(f"tcp_socks:{tcp_socks}")
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
                logger().info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                client_socket[count].connected_tcp_socket = client_socket[count]
                client_socket[count].send_data_tcp(tx_buffer)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock_no) + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger().info(f"Data received at DUT --> {buffer_rx}")
                logger().info("Data sent by remote peer and received on DUT is matching")
                count += 1
        time.sleep(3)
        ble_obj.stop_scan_adv()
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
            time.sleep(1)

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        tcp_socks.clear()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780401')
def test_Coex_sdk_WLAN_TCP_sync_socket_select_threads_BLE_scan_SI_300ms_SW_100ms_C780401(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create 4 TCP sockets,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with multiple socket descriptors
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=300,
            scan_window=100
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"],
                                          server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, wifi_obj.dut_addr["device_ip"], server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
        time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        logger().info(f"tcp_socks:{tcp_socks}")
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
                logger().info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                client_socket[count].connected_tcp_socket = client_socket[count]
                client_socket[count].send_data_tcp(tx_buffer)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock_no) + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger().info(f"Data received at DUT --> {buffer_rx}")
                logger().info("Data sent by remote peer and received on DUT is matching")
                count += 1
        time.sleep(3)
        ble_obj.stop_scan_adv()
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
            time.sleep(1)

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        tcp_socks.clear()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
        | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(4)
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
        | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
        | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 3584},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"]
)
@pytest.mark.test_src_map_id('C780402')
def test_Coex_sdk_WLAN_TCP_sync_socket_select_threads_BLE_scan_SI_900ms_SW_300ms_C780402(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Advertise BLE remote device
        5. Start Scan from DUT device
        6. Enable wlan and bt power save mode in dut after the connection
        7. Create 4 TCP sockets,Choose socket using select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with multiple socket descriptors
    """
    ble_obj = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "iperf"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )

        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan",
            scan_interval=900,
            scan_window=300
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        start_port = 5001
        client_socket = []
        tcp_socks = []
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.dut_addr["device_ip"],
                                          server_port=server_port, timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(socket_fd=sock, backlog=0, asynch=1)
            time.sleep(3)
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, wifi_obj.dut_addr["device_ip"], server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
        time.sleep(3)

        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=4, time=30)
        logger().info(f"tcp_socks:{tcp_socks}")
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            count = 0
            for sock_no in tcp_socks:
                tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1460))
                logger().info(f"Remote peer is sending data over socket {sock_no + 1} and data --> {tx_buffer}")
                client_socket[count].connected_tcp_socket = client_socket[count]
                client_socket[count].send_data_tcp(tx_buffer)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=int(sock_no) + 1, timeout=30)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{sock_no} opened in the DUT is not matched"
                logger().info(f"Data received at DUT --> {buffer_rx}")
                logger().info("Data sent by remote peer and received on DUT is matching")
                count += 1
        time.sleep(3)
        ble_obj.stop_scan_adv()
        for sock_id in tcp_socks:
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
            time.sleep(1)

        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        tcp_socks.clear()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        ble_client.interfaces.bluetooth.close()
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        if ble_obj is not None:
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)



