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
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from test_sta_ble_sdk import (
    BleThreadFunctionality,
    SnifferValidationProcess,
    ScanTime_JoinTime,
    WifiJoinThread,
)
import random
from random import randint
from utf.utils.stopwatch import Stopwatch
import string
from utf.utils.iperf.iperf_utils import ping

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
        5. Connect BLE as dualrole master&slave  
        5. data transfer

    Author: Swathi.Chinthala

"""


# this thread used for sta+ble as a slave
class BleDualRoleThreadFunctionality(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_clients=None,
        ble_test_type=None,
        sl_collections=None,
        testcase=None,
        gatt=False,
        ble_pairing=0,
        max_conn_interval=160,
        min_conn_interval=160
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.testcase = testcase
        self.gatt = gatt
        self.ble_pairing = ble_pairing
        self.max_conn_interval = max_conn_interval
        self.min_conn_interval = min_conn_interval

        if self.gatt:
            # Set up DUT for BLE advertising
            logger().info("start ble GATT service in DUT")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(
                set_smp=self.ble_pairing)
        else:
            # Set up DUT for BLE advertising
            logger().info("Initialising BLE")
            self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert (
            self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"bt_dut_address : {self.ble_dut_address}")
        time.sleep(5)
        self.ble_clients_address = []

    def dual_role_disconnect(self):

        for i in range(0, len(self.ble_clients)):
            status = self.ble_clients[i].interfaces.bluetooth.get_connection_status(
                self.ble_dut_address
            )
            logger().info(
                f"Connection status in remote device '{self.ble_clients[0].name}' is:{status}"
            )
            assert (
                status
            ), f"Remote device '{self.ble_clients[i].name}' is not connected to DUT"
            self.wifi_dut.interfaces.wifi.ble_disconnect(
                ble_remote_dev_address=self.ble_clients_address[i]
            )
            self.ble_clients[i].interfaces.bluetooth.close()

    def run(self):
        self.ble_clients_address = []
        if self.ble_test_type == "multi_slave":
            for i in range(0, len(self.ble_clients)):
                self.ble_clients_address.append(self.sl_collections.advertise_remote_device(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[i],
                    ble_dut_address=self.ble_dut_address,
                ))
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_clients_address[i],
                                                                 timeout=120)
                logger().info(f"Remote device found in scan results ,BLE scanning is successful")
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()

                self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_clients[i],
                                                ble_dut_address=self.ble_dut_address,
                                                ble_client_address=self.ble_clients_address[i],
                                                mode="master",
                                                ble_pairing=self.ble_pairing)

        if self.ble_test_type == "multi_master":
            for i in range(0, len(self.ble_clients)):
                self.ble_clients_address.append(
                    self.sl_collections.check_ble_advertise_functionality(wifi_dut=self.wifi_dut,
                                                                          ble_client=self.ble_clients[i],
                                                                          ble_dut_address=self.ble_dut_address,
                                                                          timeout=20))
                self.ble_clients[i].interfaces.bluetooth.stop_scanning()
                self.wifi_dut.interfaces.wifi.ble_scanning = False
                self.wifi_dut.interfaces.wifi.ble_advertising = False
                self.sl_collections.connect_ble(wifi_dut=self.wifi_dut, ble_client=self.ble_clients[i],
                                                ble_dut_address=self.ble_dut_address,
                                                ble_client_address=self.ble_clients_address[i],
                                                mode="slave",
                                                ble_pairing=self.ble_pairing,
                                                min_conn_interval=self.min_conn_interval,
                                                max_conn_interval=self.max_conn_interval,
                                                timeout=30)
                logger().info("BLE Connection success")

        if self.ble_test_type == "slave_and_master":
            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[0],
                    ble_dut_address=self.ble_dut_address,
                    mode="slave",
                )
            )

            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[1],
                    ble_dut_address=self.ble_dut_address,
                    mode="master",
                )
            )

        if self.ble_test_type == "master_and_slave":
            self.ble_clients_address.append(
                self.sl_collections.ble_connection(
                    wifi_dut=self.wifi_dut,
                    ble_client=self.ble_clients[0],
                    ble_dut_address=self.ble_dut_address,
                    mode="master",
                )
            )
            if "C133572" in self.testcase:

                self.ble_clients_address.append(
                    self.sl_collections.ble_connection(
                        wifi_dut=self.wifi_dut,
                        ble_client=self.ble_clients[1],
                        ble_dut_address=self.ble_dut_address,
                        mode="slave",
                        max_conn_interval=20,
                        min_conn_interval=20,
                    )
                )
            else:
                self.ble_clients_address.append(
                    self.sl_collections.ble_connection(
                        wifi_dut=self.wifi_dut,
                        ble_client=self.ble_clients[1],
                        ble_dut_address=self.ble_dut_address,
                        mode="slave"
                    )
                )



pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.Default
            | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE
                              | Si91xExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV
                              | Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(1),
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
]


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
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
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
    wifi_obj.join_to_ap(skip_power_save=True)
    ble_obj = BleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        sl_collections=sl_collections,
        ble_test_type="advertise",
    )
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
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
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
    wifi_obj.join_to_ap(skip_power_save=True)
    ble_obj = BleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_client=ble_client,
        sl_collections=sl_collections,
        ble_test_type="advertise",
    )
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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
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
    wifi_obj.join_to_ap(skip_power_save=True)

    ble_obj = BleDualRoleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_clients=ble_clients,
        sl_collections=sl_collections,
        ble_test_type="master_and_slave",
        testcase=test_name,
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.set_power_save()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    time.sleep(60)
    ble_obj.dual_role_disconnect()
    wifi_obj.disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


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
        "ble_stop_scan",
    ],
)
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
    wifi_obj.join_to_ap(skip_power_save=True)

    ble_obj = BleDualRoleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_clients=ble_clients,
        sl_collections=sl_collections,
        ble_test_type="slave_and_master",
        testcase=test_name,
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.set_power_save()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    time.sleep(60)
    ble_obj.dual_role_disconnect()
    wifi_obj.disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


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
        "ble_stop_scan",
    ],
)
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
    wifi_obj.join_to_ap(skip_power_save=True)

    ble_obj = BleDualRoleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_clients=ble_clients,
        sl_collections=sl_collections,
        ble_test_type="slave_and_master",
        testcase=test_name,
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.set_power_save()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    time.sleep(60)
    ble_obj.dual_role_disconnect()
    wifi_obj.disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


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
        "ble_stop_scan",
    ],
)
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

    ble_obj = BleDualRoleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_clients=ble_clients,
        sl_collections=sl_collections,
        ble_test_type="slave_and_master",
        testcase=test_name,
    )

    for count in range(1, iter_count + 1):

        ble_obj.start()
        ble_obj.wait_for_exit()
        if count == 1:
            wifi_obj.set_power_save()
            wifi_obj.start()
            wifi_obj.wait_for_exit()
        time.sleep(60)
        ble_obj.dual_role_disconnect()
    wifi_obj.disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
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
    wifi_obj.join_to_ap(skip_power_save=True)
    ble_obj = BleDualRoleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_clients=ble_clients,
        sl_collections=sl_collections,
        ble_test_type="master_and_slave",
        testcase=test_name,
        max_conn_interval=20,
        min_conn_interval=20
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.set_power_save()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    time.sleep(60)
    ble_obj.dual_role_disconnect()
    wifi_obj.disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")


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
        "ble_stop_scan",
    ],
)
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
        ble_test_type="master",
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


# @pytest.mark.skip("UDP Data transfer issue")
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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
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
    ble_obj = BleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_client=ble_clients[0],
        sl_collections=sl_collections,
        ble_test_type="master",
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

    for i in range(0, 3):
        found_devices = ble_clients[1].interfaces.bluetooth.get_devices()
        logger().info("\n***scan results:{}**********\n".format(found_devices))
        time.sleep(10)
    assert (
        wifi_dut.interfaces.wifi.ble_address in found_devices
    ), "DUT not found in scan results"
    logger().info(
        f"DUT BLE address:'{ble_obj.ble_dut_address}' found in raspi scan results"
    )
    ble_clients[1].interfaces.bluetooth.stop_scanning()
    ble_clients[1].interfaces.bluetooth.close()
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


# @pytest.mark.skip("UDP Data transfer issue")
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
        "ble_stop_adv",
        "ble_stop_scan",
    ],
)
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
    ble_obj = BleDualRoleThreadFunctionality(
        wifi_dut=wifi_dut,
        ble_clients=ble_clients,
        sl_collections=sl_collections,
        ble_test_type="slave_and_master",
        testcase=test_name,
    )
    ble_obj.start()
    ble_obj.wait_for_exit()
    wifi_obj.set_power_save()
    wifi_obj.start()
    wifi_obj.wait_for_exit()
    time.sleep(60)
    ble_obj.dual_role_disconnect()
    wifi_obj.disconnect()
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation_join()
    logger().info("sniffer validation is successful")




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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
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
        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="master_and_slave",
            testcase=test_name,
            gatt=True
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Fetching HeartRateService profile from RD")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_obj.ble_clients_address[0],
                                                                timeout=30)
        wifi_obj.set_power_save()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(600)
        ble_obj.dual_role_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)





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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
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
        3. Conenct DUT as BLE master
        4. Connect DUT as BLE slave
        5. Query the profiles from DUT
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping with size 300
        7. check the stability of WLAN and BLE connection for 60sec

    """
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

        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="multi_slave",
            testcase=test_name,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.join_to_ap()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        time.sleep(600)
        ble_obj.dual_role_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)


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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4365")
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
        5.


    """
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
            traffic_type="TX",
            timeout=120
        )

        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="multi_slave",
            testcase=test_name,
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.join_to_ap()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.dual_role_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)




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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4365")
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

        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="multi_master",
            testcase=test_name,
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()

        wifi_obj.join_to_ap()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        ble_obj.dual_role_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)





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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4365")
def test_Coex_sdk_ble_multi_central_UDP_RX_C133567(
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

        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="multi_master",
            testcase=test_name,
            ble_pairing=1
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.join_to_ap()
        status = ping(wifi_obj.device_ip, 300, size=300)
        assert status, "DUT NOT RESPONDING FOR PING REQUEST......"
        ble_obj.dual_role_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)





@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4365, WIFI_BT_UTFHELP-4524")
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
        "ble_stop_scan",
        "ble_stop_adv",
    ],
)
def test_Coex_sdk_gatt_rw_wr_dual_role_ssl_tx_C133510(
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
        wifi_obj.join_to_ap(skip_power_save=True)

        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="master_and_slave",
            testcase=test_name,
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.set_power_save()
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server()
        server_ip = ssl_server.interfaces.ssl.server_ip
        logger().info(f"SSL server started with server ip:{server_ip}")

        # Open ssl client socket in the DUT
        sock = wifi_dut.interfaces.wifi.socket()
        assert sock == 0, "Socket id received is wrong. expected is 0"
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP", option_val="tls_1_2")
        # Socket binds at (device_ip, port) in DUT
        local_port = randint(5001, 60000)
        wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=wifi_obj.device_ip, server_port=port1, timeout=15)
        # ssl socket opened in DUT connects to the server
        wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                  server_port=port1)
        sw = Stopwatch()
        while sw.elapsed_sec < 120:
            # The api returns 100 bytes of random data
            data = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
            logger().info(f"Sending data {data} over socket_no->{sock}")
            # DUT sends 100 bytes of data over ssl socket
            wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=sock, data=data)
            time.sleep(1)
            # SSL server receives the data over ssl socket
            server_socket_no = 1
            data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(data))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert data == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")

        wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=sock)
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()

        ble_obj.dual_role_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)




@pytest.mark.skip(reason="WIFI_BT_UTFHELP-4365")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
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
    ble_obj = None
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
        ble_obj = BleDualRoleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_clients=ble_clients,
            sl_collections=sl_collections,
            ble_test_type="master_and_slave",
            testcase=test_name,
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
            test_type="ping",

        )
        wifi_obj.join_to_ap()
        server_port_base = 5001
        tcp_socks = []
        client_socket = []
        for count in range(0, 2):
            server_port = server_port_base + count
            client_socket.append(remote_socket_factory.interfaces.socket.create_socket())
            sock = wifi_dut.interfaces.wifi.Asyncsocket(protocol="IPPROTO_TCP")
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
            wifi_dut.interfaces.wifi.bsdAsyncSockClose(socket_fd=sock)

        ble_obj.dual_role_disconnect()

        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        remote_socket_factory.interfaces.socket.close_all()
        if ble_obj:
            ble_clients[0].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            ble_clients[1].interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_clients[0],
                                       ble_client_address=ble_obj.ble_clients_address[0],
                                       ble_dut_address=ble_obj.ble_dut_address)






