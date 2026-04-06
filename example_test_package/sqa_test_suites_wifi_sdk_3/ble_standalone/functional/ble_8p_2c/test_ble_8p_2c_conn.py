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
def test_8p_2c_connection_tx_indicate_20_bytes_C768083(ble_dut, ble_client, ble_clients):

    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # 20 bytes of indication data
    indicate_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    # --- Shared synchronization primitives ---
    dut_lock = threading.Lock()          # mutex: only 1 thread talks to DUT at a time
    indicate_allowed = threading.Event() # clear = paused (scan/connect), set = running
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection.
           Pauses when indicate_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            # Block here if scan/connect is in progress
            indicate_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_indicate(
                        conn_id=conn_id,
                        data=indicate_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Indication #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Indication #{count} failed: {e}")

            time.sleep(indicate_interval)
        logger().info(f"[Client {conn_id + 1}] Indication thread stopped after {count} indications")

    def pause_indications():
        """Pause all indication threads before scan/connect."""
        logger().info(">>> Pausing all indication threads for scan/connect")
        indicate_allowed.clear()
        # Wait for any in-flight indication to finish (release the lock)
        with dut_lock:
            pass
        logger().info(">>> All indication threads paused")

    def resume_indications():
        """Resume all indication threads after scan/connect."""
        logger().info(">>> Resuming all indication threads")
        indicate_allowed.set()

    def start_indicate_thread(conn_id):
        """Start a new parallel indication thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_indicate,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        indicate_threads.append(t)
        logger().info(f"Indication thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals + start indicate after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        # Pause existing indication threads during scan/connect
        if indicate_threads:
            pause_indications()

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
        time.sleep(40)

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

        # Start indicate thread for this new connection
        start_indicate_thread(conn_id=idx)

        # Resume all indication threads (existing + new)
        resume_indications()

    # ========== PHASE 2: Connect 2 centrals + start indicate after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_indications()

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

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        # Resume all indication threads
        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all indication threads =====")

    # ========== PHASE 4: Stop all indication threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    indicate_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(indicate_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} indication thread joined")

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

    logger().info("===== Test complete! =====")





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
def test_8p_2c_connection_tx_write_no_resp_20_bytes_C768090(ble_dut, ble_client, ble_clients):

    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # 20 bytes of write data (40 hex characters = 20 bytes)
    wwr_data = "thisistwentybytesdata"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    # --- Shared synchronization primitives ---
    dut_lock = threading.Lock()       # mutex: only 1 thread talks to DUT at a time
    wwr_allowed = threading.Event()   # clear = paused (scan/connect), set = running
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection.
           Pauses when wwr_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            # Block here if scan/connect is in progress
            wwr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_no_resp(
                        conn_id=conn_id,
                        data=wwr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-no-resp #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-no-resp #{count} failed: {e}")

            time.sleep(wwr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-no-resp thread stopped after {count} writes")

    def pause_wwr():
        """Pause all write-without-response threads before scan/connect."""
        logger().info(">>> Pausing all write-no-resp threads for scan/connect")
        wwr_allowed.clear()
        # Wait for any in-flight write to finish (release the lock)
        with dut_lock:
            pass
        logger().info(">>> All write-no-resp threads paused")

    def resume_wwr():
        """Resume all write-without-response threads after scan/connect."""
        logger().info(">>> Resuming all write-no-resp threads")
        wwr_allowed.set()

    def start_wwr_thread(conn_id):
        """Start a new parallel write-without-response thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_no_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wwr_threads.append(t)
        logger().info(f"Write-no-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals + start write-no-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        # Pause existing write-no-resp threads during scan/connect
        if wwr_threads:
            pause_wwr()

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
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services to confirm GATT setup is correct
        servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        # DO NOT call enable_notifications / subscribe_to_notifications / read_charac_value
        # Those write to the CCCD which enables indications — not needed for write-no-resp

        logger().info(f"Peripheral {idx + 1} connected and ready for write-no-resp")
        time.sleep(2)

        # Start write-no-resp thread — DUT firmware resolves handles internally per conn_id
        start_wwr_thread(conn_id=idx)

        # Resume all write-no-resp threads (existing + new)
        resume_wwr()

    # ========== PHASE 2: Connect 2 centrals + start write-no-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_wwr()

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

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        # Resume all write-no-resp threads
        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-no-resp threads =====")

    # ========== PHASE 4: Stop all write-no-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wwr_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(wwr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-no-resp thread joined")

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

    logger().info("===== Test complete! =====")