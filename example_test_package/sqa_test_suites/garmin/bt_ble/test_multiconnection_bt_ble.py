import pytest
from datetime import datetime, timedelta
from utf.interfaces.bluetooth import BTSocketRole
from utf.utils.logger import get_logger
import time
from example_test_package.conftest import rs_helper_ble
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, \
    RS9116ConfigFeatureBitMap, RS9116TCPIPFeatureBitMap, \
    RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116CustomFeatureBitMap, RS9116PowerSaveProcedureTypes, \
    RS9116BTFeatureBitMap, \
    RS9116CustomFeatureBitMap, RS9116AsyncEventType
from utf.utils.logger import get_logger
from utf.interfaces.wifi import WlanError
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
import time
import threading
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase


def logger():
    return get_logger(__name__)


def clean_up_method(dut, dut_type="bt_dut"):
    time.sleep(2)
    try:
        if dut_type == "bt_dut":
            logger().info("Disabling WLAN Power Save in DUT...")
            dut.interfaces.bluetooth.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
            logger().info("Disabling BT Power Save in DUT...")
            dut.interfaces.bluetooth.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled)
        else:
            logger().info("Disabling WLAN Power Save in DUT...")
            dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveDisabled)
            logger().info("Disabling BT Power Save in DUT...")
            dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveDisabled)
    except Exception as e:
        logger().error(f"Exception: {e}")


pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake,
            "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.
                ExtTCPIPFeatureBitmapValid,
            "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
            "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
            "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.
                FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.
                EnahanceMaxPsp,
        }
    )
]


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_2ble_adv_after_ble_reconn_C20521(bt_dut, bt_client, ble_dut, ble_clients, rs_helper_ble):
    # BLE Advertising Should happen After Multiple Re-Connections
    try:
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_master_spp()
        assert bt_dut_address, f"failed to initialise bt in dut"
        logger().info(f"BT Dut address is {bt_dut_address}")

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, f"bt initialization failed on remote device"
        logger().info(f"BT client address is {bt_client_address}")

        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                             inquiry_duration_ms=20000, timeout=60, retry_counts=7)
        if not found:
            assert found, f"Unable to find remote device {bt_client_address} During DUT inquiry"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            with bt_dut.interfaces.bluetooth.run_bt_task():
                bt_client_socket.create_client()
                bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=30)
                assert addr == bt_dut_address, f"failed to connect to bt dut"
                ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                assert ping_response, f"Failed to ping BT client to DUT"
                logger().info(f"l2ping response {ping_response}")

                logger().info("==========Enables Power Save in Wifi Mode===========")
                enable_wifi_powersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifi_powersave, f"Failed to enable wifi in powersave"

                logger().info("==========Enables Power Save in BT Mode===========")
                enable_bt_powersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_powersave, f"Failed to enable BT in Powersave"
                assert addr == bt_dut_address, f"failed to connect to bt dut"
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")

            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/HCI_log_test_C91302_ble_connection_stability_dut_as_master.log_{int(time.time())}"):
                ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
                ble_remote_address = rs_helper_ble.ble_advertise_on_remote(adv_device=ble_clients[1],
                                                                           ble_dut_address=ble_dut_address)
                rs_helper_ble.ble_scanning_on_dut(scan_device=ble_dut, ble_client_address=ble_remote_address,
                                                  timeout=60)
                rs_helper_ble.ble_stop_scanning_on_dut(scan_device=ble_dut)
                rs_helper_ble.ble_connect_DUT_as_master(ble_dut=ble_dut, ble_remote=ble_clients[1],
                                                        ble_dut_address=ble_dut_address,
                                                        ble_remote_address=ble_remote_address, smp_flag=True)
                connection_time = 60
                no_of_reconnect = 4
                ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
                with BleLogs(start_collecting_logs=True,
                             bt_log_path=f"reports/HCI_log_test_C91303_ble_connect_disconnect_dut_as_slave.log_{int(time.time())}"):
                    for i in range(0, no_of_reconnect):
                        logger().info(f'\n\n ***** THIS IS {i + 1} ITERATION ***** \n\n')
                        rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
                        rs_helper_ble.ble_scanning_on_remote(scan_device=ble_clients[0], bt_dut_address=ble_dut_address)
                        rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_clients[0],
                                                                  bt_dut_address=ble_dut_address)
                        rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_clients[0],
                                                               ble_dut_address=ble_dut_address)
                        time.sleep(connection_time)
                        rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_clients[0],
                                                                 ble_dut_address=ble_dut_address)
                        ble_clients[0].interfaces.bluetooth.close()
                        time.sleep(10)
                        i = i + 1
                time.sleep(10)
                logger().info("\n\n  ***** BLE Master Disconnection *****\n\n ")
                rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_clients[1],
                                                         ble_dut_address=ble_dut_address)
                assert addr == bt_dut_address, f"failed to connect to bt dut"
                ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                assert ping_response, f"Failed to ping BT client to DUT"
                logger().info(f"l2ping response {ping_response}")
                bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)
                bt_client_socket.close()
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        clean_up_method(bt_dut)
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address,
                                  ble_remotes={ble_clients[0]: 0})


@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_bt_ble_adv_after_ble_reconn_C111106(bt_dut, bt_client, ble_dut, ble_clients, rs_helper_ble):
    # BLE Advertising Should happen After Multiple Re-Connections with 1 BLE Master and BT connection
    try:
        bt_dut_address, pin_code = bt_dut.interfaces.bluetooth.start_bt_master_spp()
        assert bt_dut_address, f"failed to initialise bt in dut"
        logger().info(f"BT Dut address is {bt_dut_address}")

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, f"bt initialization failed on remote device"
        logger().info(f"BT client address is {bt_client_address}")

        found = bt_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                             inquiry_duration_ms=20000, timeout=22, retry_counts=3)
        if not found:
            assert found, f"Unable to find remote device {bt_client_address} During DUT inquiry"

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            with bt_dut.interfaces.bluetooth.run_bt_task():
                bt_client_socket.create_client()
                bt_dut.interfaces.bluetooth.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=30)
                assert addr == bt_dut_address, f"failed to connect to bt dut"
                ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
                assert ping_response, f"Failed to ping BT client to DUT"
                logger().info(f"l2ping response {ping_response}")

                logger().info("==========Enables Power Save in Wifi Mode===========")
                enable_wifi_powersave = bt_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_wifi_powersave, f"Failed to enable wifi in powersave"

                logger().info("==========Enables Power Save in BT Mode===========")
                enable_bt_powersave = bt_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_powersave, f"Failed to enable BT in Powersave"
                assert addr == bt_dut_address, f"failed to connect to bt dut"
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")

            connection_time = 60
            no_of_reconnect = 4
            ble_dut_address = rs_helper_ble.ble_start(ble_dut=ble_dut)
            with BleLogs(start_collecting_logs=True,
                         bt_log_path=f"reports/HCI_log_test_C91303_ble_connect_disconnect_dut_as_slave.log_{int(time.time())}"):
                for i in range(0, no_of_reconnect):
                    logger().info(f'\n\n ***** THIS IS {i + 1} ITERATION ***** \n\n')
                    rs_helper_ble.ble_advertise_on_dut(adv_device=ble_dut, ble_dut_address=ble_dut_address)
                    rs_helper_ble.ble_scanning_on_remote(scan_device=ble_clients[0], bt_dut_address=ble_dut_address)
                    rs_helper_ble.ble_stop_scanning_on_remote(scan_device=ble_clients[0],
                                                              bt_dut_address=ble_dut_address)
                    rs_helper_ble.ble_connect_DUT_as_slave(ble_dut=ble_dut, ble_remote=ble_clients[0],
                                                           ble_dut_address=ble_dut_address)
                    time.sleep(connection_time)
                    rs_helper_ble.ble_disconnect_from_remote(ble_dut=ble_dut, ble_remote=ble_clients[0],
                                                             ble_dut_address=ble_dut_address)
                    ble_clients[0].interfaces.bluetooth.close()
                    time.sleep(10)
                    i = i + 1
            assert addr == bt_dut_address, f"failed to connect to bt dut"
            ping_response = bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            assert ping_response, f"Failed to ping BT client to DUT"
            logger().info(f"l2ping response {ping_response}")
            bt_dut.interfaces.bluetooth.bt_disconnect(bt_client_address)
            bt_client_socket.close()
    except Exception as e:
        logger().info("\n got exception: {}".format(str(e)))
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        rs_helper_ble.ble_cleanup(ble_dut=ble_dut, ble_dut_address=ble_dut_address,
                                  ble_remotes={ble_clients[0]: 0})
