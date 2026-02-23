import time
import pytest
import threading
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xConfigFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xBLEFeatureBitMap
)
from utf.utils import print_dict
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger

"""
    setup requirement:
        1. DUT(917-SDK) -- 10 devices (8 peripherals + 2 centrals)
        2. Raspberry PI4

        Test Steps:
        1. Initiates the DUT Coex wlan and BLE
        2. Connect slave-1, start notify thread for slave-1
        3. Pause all notifs, connect slave-2, resume notifs on slave-1 & slave-2 in parallel
        4. Repeat until all 10 connections are up with parallel notifications
        5. Run all notifications for 20 minutes
        6. Disconnect all

    Author: Ravi Nemali
"""


def logger():
    return get_logger(__name__)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
def test_8p_2c_connection_tx_notify_20_bytes_C768086(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    notify_threads = []
    stop_flags = []

    # --- Shared synchronization primitives ---
    dut_lock = threading.Lock()  # mutex: only 1 thread talks to DUT at a time
    notify_allowed = threading.Event()  # clear = paused (scan/connect), set = running
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection.
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            # Block here if scan/connect is in progress
            notify_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_notify(
                        conn_id=conn_id,
                        data=f"data_to_client{conn_id + 1}"
                    )
                    logger().info(f"[Client {conn_id + 1}] Notification #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all notification threads before scan/connect."""
        logger().info(">>> Pausing all notification threads for scan/connect")
        notify_allowed.clear()
        # Wait for any in-flight notification to finish (release the lock)
        with dut_lock:
            pass
        logger().info(">>> All notification threads paused")

    def resume_notifications():
        """Resume all notification threads after scan/connect."""
        logger().info(">>> Resuming all notification threads")
        notify_allowed.set()

    def start_notify_thread(conn_id):
        """Start a new parallel notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        notify_threads.append(t)
        logger().info(f"Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals + start notify after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        # Pause existing notification threads during scan/connect
        if notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(10)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services and subscribe
        servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=char_path,
            char_uid=char_uid
        )

        logger().info(f"Peripheral {idx + 1} connected and subscribed")
        time.sleep(2)

        # Start notify thread for this new connection
        start_notify_thread(conn_id=idx)

        # Resume all notification threads (existing + new)
        resume_notifications()

    # ========== PHASE 2: Connect 2 centrals + start notify after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        # Resume all notification threads
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 30 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all notification threads =====")

    # ========== PHASE 4: Stop all notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(notify_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} notification thread joined")

    time.sleep(2)

    # ========== PHASE 5: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    logger().info("Disconnecting central-1")
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)

    logger().info("Disconnecting central-2")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": {"wifi": {"count": 1, "stack_len": 2048}, "ble": {"count": 1, "stack_len": 2048}},
        "oper_mode": 0,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.ULPGPIOHandshake |
                    Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 |
                    Si91xFeatureBitMap.WPSSupportDisabled,
        "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client |
                          Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": Si91xExtCustomFeatureBitMap.FeatureLowPower |
                               Si91xExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE |
                               Si91xExtCustomFeatureBitMap.SL_SI91X_EXT_FEAT_FRONT_END_SWITCH_PINS_ULP_GPIO_4_5_0 |
                               Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid,
        "config_features": Si91xConfigFeatureBitMap.SL_SI91X_FEAT_SLEEP_GPIO_SEL_BITMAP |
                           Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": Si91xBTFeatureBitMap.Default,
        "ble_features": Si91xBLEFeatureBitMap.Default | (8 << 12) | (
                2 << 27) | Si91xBLEFeatureBitMap.SL_SI91X_BLE_GATT_ASYNC_ENABLE,
        "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_CONN_EVENTS |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_NUM_REC_BYTES |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_INDICATE_CONFIRMATION_FROM_HOST |
                                   Si91xBLECustomFeatureBitMap.SL_SI91X_BLE_MTU_EXCHANGE_FROM_HOST,
    },
)
def test_8p_2c_connection_tx_notify_230_bytes_C768101(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    notify_threads = []
    stop_flags = []

    # --- Shared synchronization primitives ---
    dut_lock = threading.Lock()  # mutex: only 1 thread talks to DUT at a time
    notify_allowed = threading.Event()  # clear = paused (scan/connect), set = running
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection.
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            # Block here if scan/connect is in progress
            notify_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_notify(
                        conn_id=conn_id,
                        data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                    )
                    logger().info(f"[Client {conn_id + 1}] Notification #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all notification threads before scan/connect."""
        logger().info(">>> Pausing all notification threads for scan/connect")
        notify_allowed.clear()
        # Wait for any in-flight notification to finish (release the lock)
        with dut_lock:
            pass
        logger().info(">>> All notification threads paused")

    def resume_notifications():
        """Resume all notification threads after scan/connect."""
        logger().info(">>> Resuming all notification threads")
        notify_allowed.set()

    def start_notify_thread(conn_id):
        """Start a new parallel notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        notify_threads.append(t)
        logger().info(f"Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals + start notify after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        # Pause existing notification threads during scan/connect
        if notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(10)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services and subscribe
        servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
            char_path=char_path,
            char_uid=char_uid
        )

        logger().info(f"Peripheral {idx + 1} connected and subscribed")
        time.sleep(2)

        # Start notify thread for this new connection
        start_notify_thread(conn_id=idx)

        # Resume all notification threads (existing + new)
        resume_notifications()

    # ========== PHASE 2: Connect 2 centrals + start notify after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        # Resume all notification threads
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 30 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all notification threads =====")

    # ========== PHASE 4: Stop all notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(notify_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} notification thread joined")

    time.sleep(2)

    # ========== PHASE 5: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    logger().info("Disconnecting central-1")
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)

    logger().info("Disconnecting central-2")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)