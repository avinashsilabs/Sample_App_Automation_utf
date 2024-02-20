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
from utf.utils.logger import get_logger
from test_sta_ble_sdk import BleThreadFunctionality, WifiJoinThread


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
        6. ble secure connection as slave /master with smp

    Author: Swathi.Chinthala

"""


@pytest.mark.config(
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
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST
        | Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_WLAN_TCP_UDP_RX_WPA2_BLE_slave_C133476(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Configure AP on WPA2 security
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        5. Join the access point and enable the dhcp
        6. Enable wlan and bt power save mode in dut after the connection
        7. Do Wi-Fi data transfer TCP-RX ,UDP-RX
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
            ble_test_type="slave",
        )
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.join_to_ap()
        wifi_obj.run_traffic(protocol="TCP", traffic_type="RX")
        wifi_obj.run_traffic(protocol="UDP", traffic_type="RX")
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_ADV_BLE_while_WLAN_TCP_RX_C133552(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Advertise BLE DUT
        3. Wlan Scan ,connect ,ip ,powersave,ping
        4. Run TCP RX
        5. Scan from remote BLE device
    """
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
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_from_remote_device",
        )

        ble_obj.advertise_dut()
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info("Initiating stop scan from Remote device")
        ble_client.interfaces.bluetooth.stop_scanning()
        ble_client.interfaces.bluetooth.close()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
            traffic_type="RX",
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        ble_obj.stop_adv_scan()
        ble_client.interfaces.bluetooth.close()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
def test_Coex_sdk_WLAN_TCP_RX_while_BLE_continuous_scan_C133555(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Advertise remote Raspi device
        3. Enable Scan from DUT check whether dut is able to find remote device
        4. Join the access point and enable the dhcp
        5. Enable the wlan and bt power save mode in dut after the connection
        6. Initiate ping from the dut and run TCP RX
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
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
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type="iperf",
            traffic_type="RX",
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.config("wifi_access_point", wifi={"security": "Open"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_WLAN_throughput_open_BLE_slave_C133449(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Configure AP on open security
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        5. Join the access point and enable the dhcp
        6. Enable wlan and bt power save mode in dut after the connection
        7. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
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
            ble_test_type="slave",
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
            net_perf_client=net_perf_client,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_WLAN_throughput_WPA2_BLE_slave_C133450(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Configure AP on WPA2 security
        3. Advertise BLE DUT
        4. Scan from remote BLE device and connect to DUT
        5. Join the access point and enable the dhcp
        6. Enable wlan and bt power save mode in dut after the connection
        7. Do Wi-Fi data transfer TCP-TX ,TCP-RX, UDP-TX, UDP-RX
    """
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "throughput"
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
            ble_test_type="slave",
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
            net_perf_client=net_perf_client,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
        )
        wifi_obj.start()
        wifi_obj.wait_for_exit()
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
@pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
def test_Coex_sdk_ble_bd_addr_wlan_TCP_TX_C133564(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        4. Enable the wlan and bt power save mode in dut after the connection
        5. Run TCP-TX
        6. query for local bd address
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
            net_perf_client=net_perf_client,
            protocol=protocol,
            timeout=200,
        )
        ble_obj = BleThreadFunctionality(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="scan_and_connect_from_dut",
        )
        ble_obj.advertise_remote_device()
        wifi_obj.join_to_ap()
        wifi_obj.start()
        time.sleep(10)
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_dut.interfaces.wifi.bt_get_local_address()
        wifi_obj.wait_for_exit()
        wifi_obj.disconnect()
        ble_obj.ble_disconnect(disconnect_from="dut")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation_join()
        logger().info("sniffer validation is successful")

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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
# @pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
def test_Coex_sdk_SMP_DUT_UDP_RX_C133443(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Enable wlan and bt power save mode in dut after the connection
        5. Do Wi-Fi data transfer UDP-RX
        6. Advertise BLE DUT
        7. Scan from remote BLE device and connect to DUT through smp pairing
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
            ble_test_type="master",
            ble_pairing=1,
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="RX",
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
            "wifi": {"count": 1, "stack_len": 2048},
            "ble": {"count": 1, "stack_len": 2048},
        },
    },
)
# @pytest.mark.skip()
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890"}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_scan"]
)
def test_Coex_sdk_SMP_PAIR_REQ_DUT_UDP_TX_C133441(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Enable wlan and bt power save mode in dut after the connection
        5. Do Wi-Fi data transfer UDP-tx
        6. Advertise BLE DUT
        7. Scan from remote BLE device and connect to DUT through smp pairing
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
            ble_test_type="master",
            ble_pairing=1,
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="TX",
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
@pytest.mark.config(
    "net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE}
)
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state(
    "wifi_dut", wifi=["bt_powersave_disable", "wifi_powersave_disable", "disassociated", "ble_stop_adv"]
)
def test_Coex_sdk_SMP_PAIR_RESP_DUT_TCP_TX_C133442(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
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
        2. Configure AP on WPA2 security
        3. Join the access point and enable the dhcp
        4. Enable wlan and bt power save mode in dut after the connection
        5. Do Wi-Fi data transfer TCP-TX
        6. Advertise BLE DUT
        7. Scan from remote BLE device and connect to DUT through smp pairing
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
            ble_test_type="slave",
            ble_pairing=1,
        )

        wifi_obj = WifiJoinThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            net_perf_client=net_perf_client,
            sl_collections=sl_collections,
            protocol=protocol,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            traffic_type="TX",
        )
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
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
        | Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
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
def test_Coex_sdk_SMP_WLAN_connection_data_C133565(
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
        2. Configure AP on WPA2 security
        3. Advertise BLE DUT
        4. Join the access point and enable the dhcp
        5. Enable wlan and bt power save mode in dut after the connection
        6. Ping from remote device to DUT
        8. Scan from remote BLE device and connect to DUT through smp pairing
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
            ble_test_type="scan_and_connect_from_remote",
            ble_pairing=1,
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
            traffic_type="TX",
        )
        ble_obj.advertise_dut()
        wifi_obj.join_to_ap()
        wifi_obj.start()
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.wait_for_exit()
        logger().info("Checking connection stability for 60 seconds")
        time.sleep(60)
        ble_obj.ble_disconnect()
        wifi_obj.disconnect()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("sniffer validation is successful")
        wifi_obj.sniffer_validation_join()

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
