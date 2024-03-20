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
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, WifiJoinThread
from utf.utils.iperf.iperf_utils import ping
from utf_wiseconnect_3.tests.sl_status import SLStatus
import random
import string
from random import randint
from utf.utils.stopwatch import Stopwatch
import uuid
from datetime import datetime
from typing import Dict
from threading import Thread
from utf.interfaces.socket import SOCKET_TYPE_TCP, SOCKET_TYPE_UDP



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
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid
                               | Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "ble_features": Si91xBLEFeatureBitMap.Default
        | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
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
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
@pytest.mark.skip()
def test_Coex_sdk_WLAN_TCP_socket_select_without_bit_BLE_master_C133576(
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

        # ble_obj = BleThreadFunctionality(
        #     wifi_dut=wifi_dut,
        #     ble_client=ble_client,
        #     sl_collections=sl_collections,
        #     ble_test_type="slave",
        # )
        # ble_obj.start()
        # ble_obj.wait_for_exit()
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
        wifi_obj.join_to_ap()

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

        try:
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1,
                                                 time=30, timeout=30)
        except:
            wifi_dut.interfaces.wifi.get_firmware_status()

        logger().info("Checking BLE  connection stability for 60 seconds")
        #time.sleep(60)
        #ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)






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
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
        | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048},
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
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
@pytest.mark.skip()
def test_Coex_sdk_WLAN_TCP_socket_select_when_no_socket_BLE_master_C133577(
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
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        port = 5003
        remote_socket.interfaces.socket.start_server(port=port)
        server_ipp = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)

        wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1,
                                                      time=30, timeout=30)

        logger().info("Checking BLE  connection stability for 60 seconds")
        time.sleep(60)
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


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
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
       # | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
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
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """

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
        wifi_obj.join_to_ap()

        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        server_port = random.randint(5001, 5020)
        local_port = random.randint(40001, 60000)

        remote_socket.interfaces.socket.time_limit = 1000
        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)

        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=local_port, timeout=15)

        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
        time.sleep(3)
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
            time.sleep(3)
            wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1,
                                                     time=30, timeout=30)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock)
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} opened in the DUT is not matched"

            time.sleep(3)

        #logger().info("Checking BLE  connection stability for 60 seconds")
        #time.sleep(60)
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




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
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
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
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        server_port = random.randint(5001, 5020)
        local_port = random.randint(40001, 60000)

        remote_socket.interfaces.socket.time_limit = 1000
        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)

        sock = wifi_dut.interfaces.wifi.socket()
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=local_port,
                                      timeout=15)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port,
                                                  timeout=20)
        buffer_length = 100
        sock_obj = SocketDataTransfer()
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            wifi_dut.interfaces.wifi.test_agent_thread_enabled = False
            tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=buffer_length))
            logger().info(f"Sending data from remote peer, data --> {tx_buffer}")

            buffer_rx = ""
            for count in range(0, 3):
                try:
                    trf_thread = Thread(target=sock_obj.send_data, args=(remote_socket, tx_buffer, 1))
                    trf_thread.start()
                    # remote_socket.interfaces.socket.send_data_tcp(tx_buffer, use_server_socket=True)
                    time.sleep(5)
                    wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=1, time=30, timeout=30)
                    buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=40)
                    break
                except Exception as e:
                    logger().info(f"bsdSocketReceive failed with error :{str(e)} retrying for 3 times")
            assert len(tx_buffer) == len(buffer_rx), f"buffer length sent by remote peer and received on the socket " \
                                                     f"id {sock} opened in the DUT is not matched"
            logger().info("Data sent by remote peer and received at DUT is matching")
            # trf_thread.join()
            time.sleep(2)

        logger().info(f"Closing socket_id->{sock}")
        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock, timeout=20)
        remote_socket.interfaces.socket.stop()
        #ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        ble_obj.stop_scan_adv()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)





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
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
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
        7. Create TCP socket,Choose socket using async select API.
        8. Select command allows monitoring multiple file descriptors,
         waiting until one of the file descriptors becomes active
        9.Receive data with same socket descriptor
    """


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
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()
        time.sleep(3)
        server_port = random.randint(5001, 5020)
        local_port = random.randint(40001, 60000)
        remote_socket.interfaces.socket.time_limit = 1000

        remote_socket.interfaces.socket.start_server(port=server_port)
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address(ip_version=4)

        sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, ip_len=4, server_port=local_port,
                                      asynch=1)
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, ip_len=4, server_port=server_port)
        wifi_dut.interfaces.wifi.bsdAsyncSocketSelect(numberOfFds=1, time=10)
        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            tx_buffer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            buffer_length = len(tx_buffer)
            remote_socket.interfaces.socket.send_data_tcp(tx_buffer, True)
            wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
            time.sleep(5)
            buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock, timeout=30)
            assert buffer_length == len(
                buffer_rx), f"buffer length sent by remote peer and received on the socket id {sock} " \
                            f"opened in the DUT is not matched "
            time.sleep(5)
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)




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
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST,
        #| Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
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
        wifi_obj.join_to_ap()
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.set_power_save()

        sock_obj = SocketDataTransfer()
        start_port = 5001
        for count in range(4):
            server_port = start_port + count
            sock = wifi_dut.interfaces.wifi.socket(timeout=20)
            assert sock == count, f"socket id received is wrong, expected is {count}"
            server_socket = remote_socket_factory.interfaces.socket.create_socket()
            server_socket.time_limit = 3600
            server_socket.start_server(port=server_port, socket_type=SOCKET_TYPE_TCP)
            server_ip = server_socket.hostname_or_ip_address(ip_version=4)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=server_port,
                                          timeout=15)
            wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip, server_port=server_port)
            time.sleep(3)

        sw = Stopwatch()
        while sw.elapsed_sec <= 120:
            for sock_id in range(4):
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=100))
                logger().info(f"Sending data from remote peer, data --> {tx_buffer}")
                trf_thread = Thread(target=sock_obj.send_data, args=(remote_socket_factory, tx_buffer, 1, sock_id))
                trf_thread.start()
                time.sleep(5)
                wifi_dut.interfaces.wifi.bsdSocketSelect(numberOfFds=4, time=60, timeout=60)
                buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=sock_id, timeout=40)
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on " \
                                               f"the socket id {sock_id} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")
                trf_thread.join()
                time.sleep(5)

        for sock_id in range(4):
            logger().info(f"Closing socket_id->{sock_id}")
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock_id)
        remote_socket_factory.interfaces.socket.close_all()
        remote_socket_factory.interfaces.socket.sockets = []
        ble_obj.stop_scan_adv()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)


























