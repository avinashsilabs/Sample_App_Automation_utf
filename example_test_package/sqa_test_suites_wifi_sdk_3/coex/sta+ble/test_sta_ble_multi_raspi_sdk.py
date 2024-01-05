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
    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_clients = ble_clients
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.sl_collections = sl_collections
        self.testcase = testcase
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
                        mode="slave",
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
            | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
                "wifi": {"count": 1, "stack_len": 2048},
                "ble": {"count": 1, "stack_len": 2048},
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
