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
)
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import \
    CustomNotifyCharacteristic, HealthThermometerService

from utf.interfaces.bluetooth.bluez.gatt_application.blood_pressure_service import \
    BloodPressureService, BloodPressureMeasurementCharacteristic

from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_sdk import (
    BleThreadFunctionality,
    SnifferValidationProcess,
    ScanTime_JoinTime,
    WifiJoinThread,
)
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import random
from random import randint
from utf.utils.stopwatch import Stopwatch
import string
from utf.utils.iperf.iperf_utils import ping
import re

from example_test_package.sqa_test_suites_wifi_sdk_3.coex.functional.sta_ble.test_sta_ble_dle_sdk import BleThread


def logger():
    return get_logger(__name__)

ble_obj = None

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
        5. Connect BLE as dualrole master&slave  
        5. data transfer

    Author: Swathi.Chinthala

"""


def dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address):

    for i in range(0, len(ble_clients)):
        status = ble_clients[i].interfaces.bluetooth.get_connection_status(
            ble_dut_address
        )
        logger().info(
            f"Connection status in remote device '{ble_clients[i].name}' is:{status}"
        )
        assert (
            status
        ), f"Remote device '{ble_clients[i].name}' is not connected to DUT"
        ble_clients[i].interfaces.bluetooth.disconnect(ble_dut_address)
        ble_clients[i].interfaces.bluetooth.remove_device(ble_dut_address)
        ble_clients[i].interfaces.bluetooth.close()
        time.sleep(5)





# this thread used for Wi-Fi join
class SSLdatatransfer(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
            self,
            wifi_dut=None,
            wifi_access_point=None,
            testcase=None,
            wifi_client=None,
            test_type=None,
            sl_collections=None,
            ping_count=None,
            timeout=60,
            ssl_server=None,
            device_ip=None
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.timeout = timeout
        self.ssl_server = ssl_server
        self.device_ip = device_ip

    def SSl_TX(self):
        port1 = self.ssl_server.interfaces.ssl.config['device_port1']
        self.ssl_server.interfaces.ssl.start_server()
        server_ip = self.ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = self.wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")

        self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        self.ssl_server.interfaces.ssl.stop_server()

    def run(self):
        self.SSl_TX()



def wifi_dut_marker(ext_custom_bit=0, tcp_feat_bit=0,
                    ext_tcp_feat_bit=0,
                    ca_cert=None, wifi_stack_len=3584,
                    ble_stack_len=3584, client_cert=None, num_peripheral_connections=1, num_central_connections=1,
                    wifi_thread_count=1, ble_thread_count=1):
    config = {

        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default
                    | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "tcpip_features": Si91xTCPIPFeatureBitMap.Default | tcp_feat_bit,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose | ext_tcp_feat_bit,
        "custom_features": Si91xCustomFeatureBitMap.NWP120MHz
                           | Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.Default
                               | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | ext_custom_bit,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.set_num_centrals(num_centrals=num_central_connections)
            | Si91xBLEFeatureBitMap.set_num_peripherals(num_peripherals=num_peripheral_connections)
            | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_SERV
            | Si91xBLEFeatureBitMap.BLE_MAX_NBR_ATT_REC
            | Si91xBLEFeatureBitMap.FEAT_BLE_CUSTOM_FEAT_EXTENTION_VALID
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_INX
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_PWR_SAVE_OPTIONS
            | Si91xBLEFeatureBitMap.SL_SI91X_916_BLE_COMPATIBLE_FEAT_ENABLE
            | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "thread_config": {
            "wifi": {"count": wifi_thread_count, "stack_len": wifi_stack_len, "priority": 8},
            "ble": {"count": ble_thread_count, "stack_len": ble_stack_len, "priority": 8},
        },
    }
    if ca_cert:
        config["ca_cert"] = ca_cert
    if client_cert:
        config["client_cert"] = client_cert
    return pytest.mark.config("wifi_dut", wifi=config)



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133444')
def test_Coex_sdk_ble_adv_scan_wlan_conn_C133444(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
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
            ble_test_type="advertise",
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
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )
        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_advertising()
        ble_client.interfaces.bluetooth.close()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        try:
            ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133569')
def test_Coex_sdk_ble_scan_adv_wlan_conn_C133569(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. scan& Join to the access point and enable the dhcp
        2. Advertise DUT ,Scan from remote device
        3. Advertise remote device & Scan from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate ping from the dut

    """
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
            ble_test_type="advertise",
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
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        sl_collections.check_ble_scan_functionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            ble_address=ble_obj.ble_dut_address,
            timeout=60,
        )

        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_advertising()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:

        try:
            ble_client.interfaces.bluetooth.close()
            if ble_obj is not None:
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@wifi_dut_marker()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@pytest.mark.test_src_map_id('C133507')
def test_Coex_sdk_fun_ble_master_slave_wlan_ping_C133507(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_dut_address = None
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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

        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        logger().info("Waiting for 60s for BLE connection stability.")
        time.sleep(60)
        wifi_obj.wait_for_exit()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                               ble_client_address=ble_clients_address,
                                               ble_dut_address=ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133508')
def test_Coex_sdk_fun_ble_slave_master_wlan_ping_C133508(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE slave
        4. Connect DUT as BLE master
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_dut_address = None
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=0)
        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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
        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(60)
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_clients_address,
                                           ble_dut_address=ble_dut_address)
        except Exception as e:

            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133519')
def test_Coex_sdk_fun_ble_dual_role_wlan_ping_C133519(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE slave
        4. Connect DUT as BLE master
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_dut_address = None
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=0)
        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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
        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(60)
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                               ble_client_address=ble_clients_address,
                                               ble_dut_address=ble_dut_address)

        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133550')
def test_Coex_sdk_fun_ble_dual_role_wlan_ping_C133550(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE slave
        4. Connect DUT as BLE master
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_dut_address = None
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        iter_count = utf_constants.get("iter_count")
        test_type = "ping"
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=0)
        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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
        for count in range(1, iter_count + 1):
            ble_obj1.start()
            ble_obj1.wait_for_exit()
            if count == 1:
                ble_clients_address.append(ble_obj1.ble_client_address)
            wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
            ble_obj2.start()
            ble_obj2.wait_for_exit()
            if count == 1:
                ble_clients_address.append(ble_obj2.ble_client_address)
            if count == 1:
                wifi_obj.set_power_save()
                wifi_obj.start()
                wifi_obj.wait_for_exit()
            time.sleep(60)
            dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            for ble_client in ble_clients:
                if ble_dut_address:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                       ble_client_address=ble_clients_address,
                                       ble_dut_address=ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133572')
def test_Coex_sdk_fun_ble_master_slave_20ms_wlan_ping_C133572(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave with 20ms connection interval
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_dut_address = None
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
            conn_interval=20  # 20ms connection interval
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

        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        logger().info("Waiting for 60s for BLE connection stability.")
        time.sleep(60)
        wifi_obj.wait_for_exit()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                               ble_client_address=ble_clients_address,
                                               ble_dut_address=ble_dut_address)

        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133570')
def test_Coex_sdk_discon_from_remote_wlan_conn_C133570(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE master
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate ping from the dut
        6. Disconnect from remote device while ping in progress

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
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            set_smp=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
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
        time.sleep(60)
        wifi_obj.start()
        ble_obj.ble_disconnect(disconnect_from="remote")
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)

    finally:
        try:
            if ble_obj:
                ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)
        except Exception as Ex:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133447')
def test_Coex_sdk_fun_ble_master_adv_wlan_UDP_C133447(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Conenct DUT as BLE master
        3. Start advertising DUT
        3. Join the access point and enable the dhcp
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Initiate UDP data transfer
    """
    ble_obj = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            set_smp=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        ble_obj.advertise_dut()
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
            net_perf_client=net_perf_client,
            protocol=protocol,
            traffic_type="RX",
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        logger().info("Initiating scan from Remote device")
        # Begin Scanning for BLE devices
        ble_client_address = ble_clients[1].interfaces.bluetooth.start_smp_scan(
            bt_dut_address=ble_obj.ble_dut_address
        )
        assert (
            ble_client_address is not None
        ), "Unable to fetch bluetooth address from Remote device"
        logger().info(f"Started scan from remote BLE device")
        logger().info("\n***********{}**********\n".format(ble_client_address))

        for i in range(0, 5):
            found_devices = ble_clients[1].interfaces.bluetooth.get_devices()
            logger().info("\n***scan results:{}**********\n".format(found_devices))
            time.sleep(10)
        assert (
            ble_obj.ble_dut_address in found_devices
        ), "DUT not found in scan results"
        logger().info(
            f"DUT BLE address:'{ble_obj.ble_dut_address}' found in raspi scan results"
        )

        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()

        status = ble_clients[0].interfaces.bluetooth.get_connection_status(
            ble_obj.ble_dut_address
        )
        logger().info(
            f"Connection status in remote device '{ble_clients[0].name}' is:{status}"
        )
        assert (
            status
        ), f"Remote device '{ble_clients[0].name}' is not connected to DUT"
        logger().info(f"Initiating BLE disconnection from raspi")
        ble_clients[0].interfaces.bluetooth.disconnect(ble_obj.ble_dut_address)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            for ble_client in ble_clients:
                if ble_obj:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                           ble_client_address=ble_obj.ble_client_address,
                                           ble_dut_address=ble_obj.ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True




@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133511')
def test_Coex_sdk_ble_dual_role_wlan_UDP_RX_C133511(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Start advertising DUT
        5. Initiate scan and connect from remote raspi
        6. Advertise secondary remote BLE device
        7. Initiate scan and connect from DUT
        4. Enable the wlan and bt power save mode
        5. Initiate UDP RX data transfer

    """
    ble_clients_address = []
    ble_dut_address = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=0)
        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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
            net_perf_client=net_perf_client,
            protocol=protocol,
            traffic_type="RX",
        )
        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp(set_smp=1)
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(60)
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                               ble_client_address=ble_clients_address,
                                               ble_dut_address=ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C133509')
def test_Coex_sdk_profiles_ble_master_slave_wlan_connected_C133509(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave
        5. Query the profiles from DUT
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300
        7. check the stability of WLAN and BLE connection for 60sec

    """
    ble_clients_address = []
    ble_dut_address = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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

        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        logger().info("Fetching HeartRateService profile from RD")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_clients_address[0],
                                                                timeout=30)
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_clients_address[1],
                                                                timeout=30)
        logger().info("Waiting for 60s for BLE connection stability.")
        time.sleep(60)
        wifi_obj.wait_for_exit()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                               ble_client_address=ble_clients_address,
                                               ble_dut_address=ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated"
                      ]
)
@wifi_dut_marker()
@pytest.mark.test_src_map_id('C622328')
def test_Coex_sdk_2_TCP_RX_ble_dual_role_C622328(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
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
        2. Advertise BLE DUT
        3. Wlan Scan ,connect ,ip ,powersave,ping
        4. Run TCP RX by opening 2 sockets
        6. Scan from remote BLE device
    """
    ble_clients_address = []
    ble_dut_address = None

    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_name = request.node.name
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )

        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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
            test_type="ping",

        )
        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.join_to_ap()
        server_port_base = 5001
        tcp_socks = []
        client_socket = []
        for count in range(0, 2):
            server_port = server_port_base + count
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.socket(protocol="IPPROTO_TCP")
            tcp_socks.append(sock)
            wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=server_port,
                                          timeout=15,
                                          asynch=1)
            wifi_dut.interfaces.wifi.listen(sock, backlog=0, asynch=1)
            time.sleep(3)
            ThreadBase.call_functions_simultaneously(
                [(client_socket[count].connect_client_tcp, wifi_obj.device_ip, server_port),
                 (wifi_dut.interfaces.wifi.bsdSocketAccept, sock, 1)], timeout=10)
            time.sleep(3)
        count = 0
        sw = Stopwatch()
        while sw.elapsed_sec <= 60:
            for count in range(0, len(tcp_socks)):
                tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=1460))
                buffer_length = len(tx_buffer)

                logger().info(f"Remote peer sending data over socket {tcp_socks[count]} and data:{tx_buffer}")
                client_socket[count].send_data_tcp(tx_buffer)
                time.sleep(1)
                buffer_rx = ""
                for retry in range(3):
                    try:
                        buffer_rx = wifi_dut.interfaces.wifi.bsdSocketReceive(socket_fd=tcp_socks[count] + 1,timeout=30)
                        break
                    except:
                        if retry == 2:
                            raise Exception(f"failed to receive data from the socket id {tcp_socks[count]} opened in the DUT")
                logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
                logger().info(f"###################### Buffer Data  {len(buffer_rx)}  ######################")
                logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
                assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                               f"{tcp_socks[count]} opened in the DUT is not matched"
                logger().info("Data sent by remote peer and received on DUT is matching")

        for sock in tcp_socks:
            logger().info(f"Closing socket_id->{sock}")
            wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
            time.sleep(1)

        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        time.sleep(5)

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        # logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_obj.ble_clients_address,
                                           ble_dut_address=ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True




@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
# @pytest.mark.skip("3 threads required facing issue with memory allocation in BLE DUT ")
@wifi_dut_marker(num_central_connections=2, num_peripheral_connections=0, wifi_stack_len=3584,
                    ble_stack_len=3584, ble_thread_count=2)
@pytest.mark.test_src_map_id('C538060')
def test_Coex_sdk_ble_multi_central_UDP_RX_C538060(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Connect DUT as BLE slave with remote 1
        4. Connect DUT as BLE slave with remote 2


    """
    ble_clients_address = []
    ble_dut_address = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=0)

        data1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        allocated_mem_addr1 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data1))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr1}")
        wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr1, size=len(data1), write_content=data1)
        allocated_mem_addr2 = wifi_dut.interfaces.wifi.allocate_memory(size=len(data2))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr2}")
        wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr2, size=len(data2), write_content=data2)
        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_clients_address = []

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid, data=data1,
            service_uid=service_uid,
            data_length=20, data_duration=120,
            periodic_delay=0.5,
            ble_pairing=1,
            gatt=True,
            address=allocated_mem_addr1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
            buffer_mode=1,
            buffer_count=1
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid, data=data2,
            service_uid=service_uid,
            data_length=20, data_duration=120,
            periodic_delay=0.5,
            ble_pairing=1,
            gatt=True,
            address=allocated_mem_addr2,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
            buffer_mode=1,
            buffer_count=1
        )

        # Create Custom services on DUT
        logger().info("Creating new custom gatt service in DUT")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

        # wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj1.ble_connect(role="slave")
        ble_clients_address.append(ble_obj1.ble_client_address)

        ble_obj2.ble_connect(role="slave")
        ble_clients_address.append(ble_obj2.ble_client_address)

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
            net_perf_client=net_perf_client,
            protocol=protocol,
            traffic_type="RX",
            timeout=120
        )
        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()
        ble_obj1.service_discovery_on_remote()
        ble_obj2.service_discovery_on_remote()
        wifi_obj.start()
        ble_obj1.start()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_obj1.wait_for_exit()
        wifi_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr1)
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr2)
        wifi_dut.interfaces.wifi.ble_remove_service()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_dut_address is not None:
            for ble_client in ble_clients:
                ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                       ble_client_address=ble_clients_address,
                                       ble_dut_address=ble_dut_address)



@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker(num_central_connections=2, num_peripheral_connections=0)
@pytest.mark.test_src_map_id('C133567')
def test_Coex_sdk_ble_multi_central_ping_C133567(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Connect DUT as BLE slave with remote 1
        4. Connect DUT as BLE slave with remote 2


    """
    ble_clients_address = []
    ble_dut_address = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=0)
        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="slave",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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
        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.join_to_ap(skip_power_save=True)
        wifi_obj.set_power_save()
        status = ping(wifi_obj.device_ip, 300, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_dut_address is not None:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_clients_address,
                                           ble_dut_address=ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



# @pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
        "clear_certs"
    ],
)
@wifi_dut_marker(
                 ext_custom_bit=Si91xExtCustomFeatureBitMap.Feature320kBMemoryMode,
                 tcp_feat_bit=Si91xTCPIPFeatureBitMap.SSL,
                 ca_cert=["ca-chain.cert.pem", "SL_NET_SIGNING_CERTIFICATE", "SL_NET_TLS_SERVER_CREDENTIAL_START"],
                 wifi_stack_len=3584,
                 ble_stack_len=3584,
                 wifi_thread_count=1, ble_thread_count=2
                 )
# @pytest.mark.skip("3 threads required facing issue with memory allocation in BLE DUT ")
@pytest.mark.test_src_map_id('C133510')
def test_Coex_sdk_gatt_rd_wr_dual_role_ssl_tx_C133510(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    ssl_server
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_obj = None
    allocated_mem_addr= None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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
        # Set up DUT for BLE advertising
        logger().info("start ble GATT service in DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1, bond_info=0)

        data1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data1))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data1), write_content=data1)
        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_clients_address = []

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid, data=data1,
            service_uid=service_uid,
            data_length=20, data_duration=120,
            periodic_delay=0,
            ble_pairing=1,
            gatt=True,
            address=allocated_mem_addr,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            bond_info=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            data=data2,
            set_smp=1,
            svc=svc,
            charc=charc,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        # Create Custom services on DUT
        logger().info("Creating new custom gatt service in DUT")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")

        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj2.ble_connect(role="master")
        ble_clients_address.append(ble_obj2.ble_client_address)
        ble_obj2.service_discovery_on_dut()

        ble_obj1.ble_connect(role="slave")
        ble_clients_address.append(ble_obj1.ble_client_address)
        wifi_obj.set_power_save()
        ssl_obj = SSLdatatransfer(
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            test_type=test_type,
            sl_collections=sl_collections,
            ping_count=ping_count,
            ssl_server=ssl_server,
            device_ip=wifi_obj.device_ip
        )
        ssl_obj.start()
        ble_obj1.service_discovery_on_remote()
        ble_obj1.start()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_obj1.wait_for_exit()
        ssl_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        wifi_dut.interfaces.wifi.ble_remove_service()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
            for ble_client in ble_clients:
                ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                       ble_client_address=ble_clients_address,
                                       ble_dut_address=ble_dut_address)


@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker(wifi_stack_len=3584,
                 ble_stack_len=3584,
                 wifi_thread_count=1, ble_thread_count=2
                 )
# @pytest.mark.skip("3 threads required facing issue with memory allocation in BLE DUT ")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"5MB.htm"})
# @pytest.mark.skip()
@pytest.mark.test_src_map_id('C538059')
def test_Coex_sdk_gatt_rw_wr_dual_role_http_download_C538059(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    http_server,
    index_path
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300

    """
    ble_obj = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "http"
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
            http_server=http_server,
            index_path=index_path
        )
        # Set up DUT for BLE advertising
        logger().info("start ble GATT service in DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1, bond_info=0)

        data1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        data2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data1))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data1), write_content=data1)
        service_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
        char_uid = "00001bb1-0000-1000-8000-00805f9b34fb"
        svc = 'HealthThermometerService'
        charc = 'CustomNotifyCharacteristic'
        ble_clients_address = []

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="notify_tx",
            dev_state=8,
            char_path=None, char_uid=char_uid, data=data1,
            service_uid=service_uid,
            data_length=20, data_duration=120,
            periodic_delay=0,
            ble_pairing=1,
            gatt=True,
            address=allocated_mem_addr,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )

        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="notify_rx",
            dev_state=8,
            data_duration=120,
            service_class=["HealthThermometerService"],
            gatt=True,
            ble_pairing=1,
            bond_info=1,
            service_uuid=HealthThermometerService.UUID,
            char_uuid=CustomNotifyCharacteristic.CUSTOM_NOTIFY_UUID,
            characteristic=CustomNotifyCharacteristic,
            data=data2,
            set_smp=1,
            svc=svc,
            charc=charc,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        # Create Custom services on DUT
        logger().info("Creating new custom gatt service in DUT")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x1AA1)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1BB1, permissions=34)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1BB1, data="data")
        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj2.ble_connect(role="master")
        ble_clients_address.append(ble_obj2.ble_client_address)
        ble_obj2.service_discovery_on_dut()
        wifi_dut.interfaces.wifi.ble_set_smp()
        ble_obj1.ble_connect(role="slave")
        ble_clients_address.append(ble_obj1.ble_client_address)
        ble_obj1.service_discovery_on_remote()
        wifi_obj.set_power_save()
        wifi_obj.start()
        ble_obj1.start()
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_obj1.wait_for_exit()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        wifi_dut.interfaces.wifi.memory_free(address=allocated_mem_addr)
        wifi_dut.interfaces.wifi.ble_remove_service()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            for ble_client in ble_clients:
                ble_client.interfaces.bluetooth.remove_device(ble_dut_address)
                ble_client.interfaces.bluetooth.close()
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                       ble_client_address=ble_clients_address,
                                       ble_dut_address=ble_dut_address)


        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)

@wifi_dut_marker(num_central_connections=0, num_peripheral_connections=2)
@pytest.mark.test_src_map_id('C133518')
def test_Coex_sdk_ble_multi_slave_wlan_connected_C133518(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Connect DUT as BLE master with remote1 as slave
        4. Connect DUT as BLE master with remote2 as slave
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300
        7. check the stability of WLAN and BLE connection for 60sec

    """
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
        )
        ble_obj2 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[1],
            sl_collections=sl_collections,
            ble_test_type="master",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
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

        ble_obj1.start()
        ble_obj1.wait_for_exit()
        ble_clients_address.append(ble_obj1.ble_client_address)
        ble_obj2.start()
        ble_obj2.wait_for_exit()
        ble_clients_address.append(ble_obj2.ble_client_address)
        wifi_obj.set_power_save()
        wifi_obj.start()
        logger().info("Waiting for 60s for BLE connection stability.")
        time.sleep(60)
        wifi_obj.wait_for_exit()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        try:
            if ble_obj:
                for ble_client in ble_clients:
                    ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
                    ble_client.interfaces.bluetooth.close()
                sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
                                           ble_client_address=ble_obj.ble_clients_address,
                                           ble_dut_address=ble_obj.ble_dut_address)
        except Exception as e:
            wifi_dut.interfaces.wifi.is_dut_bad_state = True



@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut",
    wifi=[
        "bt_powersave_disable",
        "wifi_powersave_disable",
        "disassociated",
    ],
)
@wifi_dut_marker(num_central_connections=0, num_peripheral_connections=2, ble_stack_len=3584, wifi_stack_len=3584)
@pytest.mark.skip()
@pytest.mark.test_src_map_id('C538058')
def test_Coex_sdk_ble_multi_peripheral_UDP_TX_C538058(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_clients,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    net_perf_client,
    protocol,
):
    """
    Test Steps:
        1. Configure the DUT in Wlan+BLE mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave
    """
    ble_clients_address = []
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
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

        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start(
            set_smp=1)

        data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
        svc = 'BloodPressureService'
        charc = 'BloodPressureMeasurementCharacteristic'
        allocated_mem_addr = wifi_dut.interfaces.wifi.allocate_memory(size=len(data))
        logger().info(f"allocated_mem_addr: {allocated_mem_addr}")
        wifi_dut.interfaces.wifi.load_memory(address=allocated_mem_addr, size=len(data), write_content=data)

        ble_obj1 = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_clients[0],
            sl_collections=sl_collections,
            ble_test_type="indications_rx",
            dev_state=8,
            ble_pairing=1,
            ble_init_required=False,
            ble_dut_address=ble_dut_address,
            service_class=["BloodPressureService"],
            service_uuid=BloodPressureService.UUID,
            char_uuid=BloodPressureMeasurementCharacteristic.BP_Measure_UUID.lower(),
            characteristic=BloodPressureMeasurementCharacteristic,
            data=data,
            data_length= 20,
            svc=svc,
            charc=charc,
            address=allocated_mem_addr,
        )
        # ble_obj2 = BleThread(
        #     wifi_dut=wifi_dut,
        #     ble_client=ble_clients[1],
        #     sl_collections=sl_collections,
        #     ble_test_type="master",
        #     dev_state=8,
        #     ble_pairing=1,
        #     ble_init_required=False,
        #     ble_dut_address=ble_dut_address,
        # )

        # wifi_obj = WifiJoinThread(
        #     wifi_sniffer=wifi_sniffer,
        #     wifi_dut=wifi_dut,
        #     wifi_access_point=wifi_access_point,
        #     testcase=test_name,
        #     wifi_client=wifi_client,
        #     sl_collections=sl_collections,
        #     ping_count=ping_count,
        #     sniffer_filter=sniffer_filter,
        #     test_type=test_type,
        #     net_perf_client=net_perf_client,
        #     protocol=protocol,
        #     traffic_type="TX",
        #     timeout=120
        # )

        # ble_obj1.start()
        # ble_obj1.wait_for_exit()

        ble_obj1.ble_connect(role="master")
        ble_clients_address.append(ble_obj1.ble_client_address)
        ble_obj1.service_discovery_on_dut()
        # # Configure Buffer Mode
        # ble_obj1.configure_buffer_mode(mode=0, count=2)
        ble_obj1.start()
        ble_obj1.wait_for_exit()

        # ble_clients_address.append(ble_obj2.ble_client_address)

        # wifi_obj.join_to_ap()
        # wifi_obj.start()
        # wifi_obj.wait_for_exit()
        dual_role_disconnect(wifi_dut, ble_clients, ble_clients_address, ble_dut_address)
        # wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        # wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    # finally:
    #     try:
    #         if ble_obj:
    #             for ble_client in ble_clients:
    #                 ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
    #                 ble_client.interfaces.bluetooth.close()
    #             sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients,
    #                                        ble_client_address=ble_obj.ble_clients_address,
    #                                        ble_dut_address=ble_obj.ble_dut_address)
    #     except Exception as e:
    #         wifi_dut.interfaces.wifi.is_dut_bad_state = True
