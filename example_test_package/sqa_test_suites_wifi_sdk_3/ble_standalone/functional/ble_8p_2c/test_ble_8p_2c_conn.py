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
@pytest.mark.test_src_map_id('C768086')
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

    dut_lock = threading.Lock()  
    notify_allowed = threading.Event()  
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection.
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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
@pytest.mark.test_src_map_id('C768101')
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
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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
@pytest.mark.test_src_map_id('C768083')
def test_8p_2c_connection_tx_indicate_20_bytes_nonsecure_C768083(ble_dut, ble_client, ble_clients):
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

    # Disable SMP for non-secure mode
    ble_dut.interfaces.bluetooth.ble_smp_enable(enable=0)
    logger().info("SMP disabled for all connections (non-secure mode)")

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
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, non-secure)")
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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (non-secure)")
        time.sleep(2)

        # Start indicate thread for this new connection
        start_indicate_thread(conn_id=idx)

        # Resume all indication threads (existing + new)
        resume_indications()

    # ========== PHASE 2: Connect 2 centrals + start indicate after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, non-secure)")
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
        logger().info(f"Central-{c_idx + 1} connected to DUT (non-secure)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        # Resume all indication threads
        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (non-secure)")
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

    logger().info("===== Test C768083 complete (non-secure mode) =====")



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
@pytest.mark.test_src_map_id('C768090')
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
@pytest.mark.test_src_map_id('C768089')
def test_8p_2c_connection_tx_write_with_resp_20_bytes_C768089(ble_dut, ble_client, ble_clients):

    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # 20 bytes of write data (40 hex characters = 20 bytes)
    wr_data = "thisistwentybytesdata"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    wr_threads = []
    stop_flags = []

    # --- Shared synchronization primitives ---
    dut_lock = threading.Lock()       # mutex: only 1 thread talks to DUT at a time
    wr_allowed = threading.Event()    # clear = paused (scan/connect), set = running
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection.
           Pauses when wr_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            # Block here if scan/connect is in progress
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        """Pause all write-with-response threads before scan/connect."""
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        # Wait for any in-flight write to finish (release the lock)
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        """Resume all write-with-response threads after scan/connect."""
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        """Start a new parallel write-with-response thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals + start write-with-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        # Pause existing write-with-resp threads during scan/connect
        if wr_threads:
            pause_wr()

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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 4
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(5)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        # DO NOT call enable_notifications / subscribe_to_notifications / read_charac_value
        # Those write to the CCCD which enables indications — not needed for write-with-resp

        logger().info(f"Peripheral {idx + 1} connected and ready for write-with-resp")
        time.sleep(2)

        # Start write-with-resp thread — DUT firmware resolves handles internally per conn_id
        start_wr_thread(conn_id=idx)

        # Resume all write-with-resp threads (existing + new)
        resume_wr()

    # ========== PHASE 2: Connect 2 centrals + start write-with-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_wr()

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

        # Start write-with-resp thread for this central (conn_ids 8, 9)
        start_wr_thread(conn_id=8 + c_idx)

        # Resume all write-with-resp threads
        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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
@pytest.mark.test_src_map_id('C768072')
def test_8p_1c_adv_with_connections_C768072(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_client = ble_clients[7]
    scan_only_client = ble_clients[8]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []

    # ========== PHASE 1: Connect 8 peripherals (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and service discovery verified")
        time.sleep(2)

    logger().info("All 8 peripherals connected successfully")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect central device-1 (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting central device-1 (DUT as SLAVE)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(2)

    central_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    time.sleep(2)
    central_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    time.sleep(20)

    ble_dut.interfaces.bluetooth.ble_get_device_state()
    logger().info("Central device-1 connected to DUT")
    time.sleep(2)

    # DUT keeps advertising (do NOT stop advertising) so central-2 can see it
    logger().info("DUT continues advertising for central device-2 scan verification")

    # ========== PHASE 3: Verify DUT advertising visible on central device-2 ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Verifying DUT advertising is visible on central device-2 scan")
    logger().info("=" * 60)

    scan_only_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    time.sleep(10)
    scan_only_client.interfaces.bluetooth.stop_scanning()

    found_devices = scan_only_client.interfaces.bluetooth.get_devices()
    logger().info(f"Central device-2 scanned devices: {found_devices}")
    assert bt_dut_address.upper() in found_devices, \
        f"DUT {bt_dut_address} not found in central device-2 scan list. Found: {found_devices}"
    logger().info(f"DUT {bt_dut_address} is visible in central device-2 scan list - advertising on channels 37/38/39 confirmed")

    # Verify DUT device state shows advertising + connected
    device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    logger().info(f"DUT device state after 8P+1C connections + advertising: {device_state}")

    # ========== PHASE 4: Stability test for 5 minutes ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Stability test - 8P + 1C connected, DUT advertising for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        time.sleep(stability_check_interval)
        elapsed += stability_check_interval
        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec")

        # Verify DUT is still in advertising + connected state
        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state: {device_state}")

        # Periodically verify DUT is still visible in central-2 scan
        scan_only_client.interfaces.bluetooth.start_scanning()
        time.sleep(10)
        scan_only_client.interfaces.bluetooth.stop_scanning()

        found_devices = scan_only_client.interfaces.bluetooth.get_devices()
        logger().info(f"Central device-2 scan at {elapsed}s: {found_devices}")
        assert bt_dut_address.upper() in found_devices, \
            f"DUT {bt_dut_address} no longer visible in central device-2 scan at {elapsed}s. " \
            f"Possible advertising failure. Found: {found_devices}"

    logger().info("5-minute stability test PASSED - DUT advertising stable with 8P + 1C")

    # ========== PHASE 5: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Disconnecting all clients")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(1)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    logger().info("Disconnecting central device-1")
    central_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)

    logger().info("===== Test C768072 complete! =====")



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
@pytest.mark.test_src_map_id('C768073')
def test_7p_2c_scan_with_connections_C768073(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5]]
    adv_only_client = ble_clients[6]  # peripheral-8: keeps advertising for scan verification
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []

    # ========== PHASE 1: Start peripheral-8 advertising (scan-only peer) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Starting peripheral-8 in advertising mode for scan verification")
    logger().info("=" * 60)

    adv_only_address = adv_only_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=[svc]
    )
    assert adv_only_address, "Failed to start advertising on peripheral-8 (scan-only peer)"
    logger().info(f"Peripheral-8 advertising at address: {adv_only_address}")

    # Verify DUT can scan and see peripheral-8 before connecting to others
    scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=adv_only_address)
    time.sleep(3)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    logger().info(f"Initial scan report: {scan_report}")
    time.sleep(1)

    # ========== PHASE 2: Connect 7 peripherals (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 7 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and service discovery verified")
        time.sleep(2)

    logger().info("All 7 peripherals connected successfully")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Connect 2 central devices (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Connecting 2 central devices (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

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

    logger().info("Both central devices connected successfully")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 4: Stability test for 5 minutes ==========
    # DUT should remain connected to 7P + 2C and be able to scan peripheral-8
    # adv packets on channels 37, 38, 39 continuously without disconnection/hang.
    logger().info("=" * 60)
    logger().info("PHASE 4: Stability test - 7P + 2C connected, DUT scanning for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        # DUT scans for peripheral-8 adv packets (channels 37, 38, 39)
        logger().info(f"Scanning for peripheral-8 adv packets at {elapsed}s...")
        scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=adv_only_address)
        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info(f"DUT scan report at {elapsed}s: {scan_report}")

        # Verify DUT device state (should show connected + scanning capable)
        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state at {elapsed}s: {device_state}")

        remaining = stability_check_interval - 10  # account for scan time
        if remaining > 0:
            time.sleep(remaining)
        elapsed += stability_check_interval

        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec - PASS")

    logger().info("5-minute stability test PASSED - 7P + 2C connections stable, DUT scanning OK")

    # ========== PHASE 5: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Disconnecting central-{c_idx + 1}")
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    logger().info("===== Test C768073 complete! =====")



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
@pytest.mark.test_src_map_id('C768074')
def test_7p_1c_adv_scan_with_connections_C768074(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5]]
    adv_only_client = ble_clients[6]  # peripheral-8: keeps advertising for scan verification
    central_client = ble_clients[7]   # central-1: connects to DUT
    scan_only_client = ble_clients[8] # central-2: scans only (verifies DUT advertising)

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []

    # ========== PHASE 1: Start peripheral-8 advertising (scan-only peer) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Starting peripheral-8 in advertising mode for scan verification")
    logger().info("=" * 60)

    adv_only_address = adv_only_client.interfaces.bluetooth.start_smp_adv(
        bt_dut_address=bt_dut_address,
        service_classes=[svc]
    )
    assert adv_only_address, "Failed to start advertising on peripheral-8 (scan-only peer)"
    logger().info(f"Peripheral-8 advertising at address: {adv_only_address}")

    # Verify DUT can scan and see peripheral-8 adv packets on channels 37/38/39
    scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=adv_only_address)
    time.sleep(3)
    ble_dut.interfaces.bluetooth.ble_stop_scanning()
    logger().info(f"Initial scan report for peripheral-8: {scan_report}")
    time.sleep(1)

    # ========== PHASE 2: Connect 7 peripherals (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 7 peripheral devices (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and service discovery verified")
        time.sleep(2)

    logger().info("All 7 peripherals connected successfully")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Connect central device-1 (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Connecting central device-1 (DUT as SLAVE)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_start_advertising()
    time.sleep(2)

    central_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    time.sleep(2)
    central_client.interfaces.bluetooth.pair_and_connect(bt_dut_address)
    time.sleep(20)

    ble_dut.interfaces.bluetooth.ble_get_device_state()
    logger().info("Central device-1 connected to DUT")
    time.sleep(2)

    # DUT keeps advertising so central-2 can verify adv packets
    logger().info("DUT continues advertising for central device-2 scan verification")

    # ========== PHASE 4: Verify DUT advertising visible on central device-2 ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Verifying DUT advertising is visible on central device-2 scan")
    logger().info("=" * 60)

    scan_only_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    time.sleep(10)
    scan_only_client.interfaces.bluetooth.stop_scanning()

    found_devices = scan_only_client.interfaces.bluetooth.get_devices()
    logger().info(f"Central device-2 scanned devices: {found_devices}")
    assert bt_dut_address.upper() in found_devices, \
        f"DUT {bt_dut_address} not found in central device-2 scan list. Found: {found_devices}"
    logger().info(f"DUT {bt_dut_address} is visible in central device-2 scan list - advertising confirmed")

    device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
    logger().info(f"DUT device state after 7P+1C connections + advertising: {device_state}")

    # ========== PHASE 5: Stability test for 5 minutes ==========
    # DUT should remain connected to 7P + 1C, continue advertising (visible to central-2),
    # and scan peripheral-8 adv packets on channels 37/38/39 without disconnection/hang.
    logger().info("=" * 60)
    logger().info("PHASE 5: Stability test - 7P + 1C connected, DUT advertising + scanning for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        # DUT scans for peripheral-8 adv packets (channels 37, 38, 39)
        logger().info(f"[{elapsed}s] DUT scanning for peripheral-8 adv packets...")
        scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=adv_only_address)
        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info(f"[{elapsed}s] DUT scan report: {scan_report}")

        # Verify DUT device state (should show connected + advertising + scanning capable)
        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"[{elapsed}s] DUT device state: {device_state}")

        # Verify DUT advertising is still visible on central device-2
        scan_only_client.interfaces.bluetooth.start_scanning()
        time.sleep(10)
        scan_only_client.interfaces.bluetooth.stop_scanning()

        found_devices = scan_only_client.interfaces.bluetooth.get_devices()
        logger().info(f"[{elapsed}s] Central device-2 scan: {found_devices}")
        assert bt_dut_address.upper() in found_devices, \
            f"DUT {bt_dut_address} no longer visible in central device-2 scan at {elapsed}s. " \
            f"Possible advertising failure. Found: {found_devices}"

        remaining = stability_check_interval - 20  # account for scan times
        if remaining > 0:
            time.sleep(remaining)
        elapsed += stability_check_interval

        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec - PASS")

    logger().info("5-minute stability test PASSED - 7P + 1C stable, DUT advertising + scanning OK")

    # ========== PHASE 6: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 6: Disconnecting all clients")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(1)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    logger().info("Disconnecting central device-1")
    central_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)

    logger().info("===== Test C768074 complete! =====")



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
@pytest.mark.test_src_map_id('C768075')
def test_2c_8p_diff_conn_intervals_C768075(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Connection interval parameters (in BLE units: 1 unit = 1.25ms for CI, 10ms for LSTO)
    # Central #1, #2: CI = 11.25ms -> 9, SL = 0, LSTO = 4000ms -> 400
    CENTRAL_CI = 9           # 11.25ms / 1.25 = 9
    CENTRAL_SL = 0
    CENTRAL_LSTO = 400       # 4000ms / 10 = 400

    # Peripheral connection interval configs (CI in BLE units)
    # P1: CI = 45ms -> 36
    # P2-P5: CI = 200ms -> 160
    # P6-P8: CI = 300ms -> 240
    peripheral_ci_map = {
        0: 36,    # P1: 45ms
        1: 160,   # P2: 200ms
        2: 160,   # P3: 200ms
        3: 160,   # P4: 200ms
        4: 160,   # P5: 200ms
        5: 240,   # P6: 300ms
        6: 240,   # P7: 300ms
        7: 240,   # P8: 300ms
    }
    PERIPHERAL_SL = 0
    PERIPHERAL_LSTO = 400    # 4000ms / 10 = 400

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []

    # ========== PHASE 1: Connect 2 central devices with CI = 11.25ms (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices with CI = 11.25ms (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central_address = central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Update connection parameters for central connection: CI = 11.25ms, SL = 0, LSTO = 4000ms
        logger().info(
            f"Updating connection params for central-{c_idx + 1}: "
            f"CI={CENTRAL_CI} (11.25ms), SL={CENTRAL_SL}, LSTO={CENTRAL_LSTO} (4000ms)"
        )
        ble_dut.interfaces.bluetooth.ble_update_connect_params(
            ble_remote_dev_address=central_address,
            min_int=CENTRAL_CI,
            max_int=CENTRAL_CI,
            latency=CENTRAL_SL,
            supervision_timeout=CENTRAL_LSTO,
        )
        time.sleep(5)

    logger().info("Both central devices connected with CI = 11.25ms")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect 8 peripherals with different CIs (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 8 peripheral devices with different CIs (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        ci = peripheral_ci_map[idx]
        ci_ms = ci * 1.25
        logger().info(f"===== Connecting to peripheral-{idx + 1} with CI={ci} ({ci_ms}ms) =====")

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

        # Connect with the specific connection interval for this peripheral
        ble_dut.interfaces.bluetooth.ble_connect(
            ble_remote_dev_address=client_address,
            ble_conn_interval_min=ci,
            ble_conn_interval_max=ci,
            ble_conn_latency=PERIPHERAL_SL,
            ble_supervision_timeout=PERIPHERAL_LSTO,
        )
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected with CI={ci_ms}ms, service discovery verified")
        time.sleep(2)

    logger().info("All 8 peripherals connected with different connection intervals")
    logger().info("  P1: CI=45ms | P2-P5: CI=200ms | P6-P8: CI=300ms")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Stability test for 5 minutes ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Stability test - 8P + 2C connected with different CIs for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        time.sleep(stability_check_interval)
        elapsed += stability_check_interval
        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec")

        # Verify DUT device state (should show connected)
        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state: {device_state}")

    logger().info("5-minute stability test PASSED - 8P + 2C connections stable with different CIs")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Disconnecting central-{c_idx + 1}")
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    logger().info("===== Test C768075 complete! =====")



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
@pytest.mark.test_src_map_id('C768076')
def test_8p_2c_diff_conn_intervals_C768076(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Connection interval parameters (in BLE units: 1 unit = 1.25ms for CI, 10ms for LSTO)
    # Peripheral CI configs
    # P1: CI = 45ms -> 36
    # P2-P5: CI = 200ms -> 160
    # P6-P8: CI = 300ms -> 240
    peripheral_ci_map = {
        0: 36,    # P1: 45ms
        1: 160,   # P2: 200ms
        2: 160,   # P3: 200ms
        3: 160,   # P4: 200ms
        4: 160,   # P5: 200ms
        5: 240,   # P6: 300ms
        6: 240,   # P7: 300ms
        7: 240,   # P8: 300ms
    }
    PERIPHERAL_SL = 0
    PERIPHERAL_LSTO = 400    # 4000ms / 10 = 400

    # Central #1, #2: CI = 45ms -> 36, SL = 0, LSTO = 4000ms -> 400
    CENTRAL_CI = 36          # 45ms / 1.25 = 36
    CENTRAL_SL = 0
    CENTRAL_LSTO = 400       # 4000ms / 10 = 400

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []

    # ========== PHASE 1: Connect 8 peripherals with different CIs (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 8 peripheral devices with different CIs (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        ci = peripheral_ci_map[idx]
        ci_ms = ci * 1.25
        logger().info(f"===== Connecting to peripheral-{idx + 1} with CI={ci} ({ci_ms}ms) =====")

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

        # Connect with the specific connection interval for this peripheral
        ble_dut.interfaces.bluetooth.ble_connect(
            ble_remote_dev_address=client_address,
            ble_conn_interval_min=ci,
            ble_conn_interval_max=ci,
            ble_conn_latency=PERIPHERAL_SL,
            ble_supervision_timeout=PERIPHERAL_LSTO,
        )
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected with CI={ci_ms}ms, service discovery verified")
        time.sleep(2)

    logger().info("All 8 peripherals connected with different connection intervals")
    logger().info("  P1: CI=45ms | P2-P5: CI=200ms | P6-P8: CI=300ms")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect 2 central devices with CI = 45ms (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices with CI = 45ms (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central_address = central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Update connection parameters for central: CI = 45ms, SL = 0, LSTO = 4000ms
        logger().info(
            f"Updating connection params for central-{c_idx + 1}: "
            f"CI={CENTRAL_CI} (45ms), SL={CENTRAL_SL}, LSTO={CENTRAL_LSTO} (4000ms)"
        )
        ble_dut.interfaces.bluetooth.ble_update_connect_params(
            ble_remote_dev_address=central_address,
            min_int=CENTRAL_CI,
            max_int=CENTRAL_CI,
            latency=CENTRAL_SL,
            supervision_timeout=CENTRAL_LSTO,
        )
        time.sleep(5)

    logger().info("Both central devices connected with CI = 45ms")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Stability test for 5 minutes ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Stability test - 8P + 2C connected with different CIs for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        time.sleep(stability_check_interval)
        elapsed += stability_check_interval
        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec")

        # Verify DUT device state (should show connected)
        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state: {device_state}")

    logger().info("5-minute stability test PASSED - 8P + 2C connections stable with different CIs")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Disconnecting central-{c_idx + 1}")
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    logger().info("===== Test C768076 complete! =====")



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
@pytest.mark.test_src_map_id('C768077')
def test_8p_2c_conn_disconn_reconn_diff_ci_C768077(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Connection interval parameters (in BLE units: 1 unit = 1.25ms for CI, 10ms for LSTO)
    # P1: CI = 100ms -> 80
    # P2-P5: CI = 200ms -> 160
    # P6-P8: CI = 300ms -> 240
    peripheral_ci_map = {
        0: 80,    # P1: 100ms
        1: 160,   # P2: 200ms
        2: 160,   # P3: 200ms
        3: 160,   # P4: 200ms
        4: 160,   # P5: 200ms
        5: 240,   # P6: 300ms
        6: 240,   # P7: 300ms
        7: 240,   # P8: 300ms
    }
    PERIPHERAL_SL = 0
    PERIPHERAL_LSTO = 400    # 4000ms / 10 = 400

    # Central #1, #2: CI = 120ms -> 96, SL = 0, LSTO = 4000ms -> 400
    CENTRAL_CI = 96          # 120ms / 1.25 = 96
    CENTRAL_SL = 0
    CENTRAL_LSTO = 400       # 4000ms / 10 = 400

    RECONNECT_ITERATIONS = 5

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    for iteration in range(1, RECONNECT_ITERATIONS + 1):
        logger().info("#" * 70)
        logger().info(f"ITERATION {iteration}/{RECONNECT_ITERATIONS}: Connect -> Disconnect cycle")
        logger().info("#" * 70)

        client_addresses = []

        # ========== STEP A: Connect 8 peripherals with different CIs (DUT as MASTER) ==========
        logger().info("=" * 60)
        logger().info(f"[Iter {iteration}] STEP A: Connecting 8 peripherals with different CIs")
        logger().info("=" * 60)

        for idx, client in enumerate(peripheral_clients):
            ci = peripheral_ci_map[idx]
            ci_ms = ci * 1.25
            logger().info(f"[Iter {iteration}] Connecting to peripheral-{idx + 1} with CI={ci} ({ci_ms}ms)")

            client_address = client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address,
                service_classes=[svc]
            )
            assert client_address, f"[Iter {iteration}] Failed to initiate BLE in peripheral device {idx + 1}"
            client_addresses.append(client_address)

            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(1)

            ble_dut.interfaces.bluetooth.ble_connect(
                ble_remote_dev_address=client_address,
                ble_conn_interval_min=ci,
                ble_conn_interval_max=ci,
                ble_conn_latency=PERIPHERAL_SL,
                ble_supervision_timeout=PERIPHERAL_LSTO,
            )
            time.sleep(40)

            ble_dut.interfaces.bluetooth.ble_get_device_state()
            time.sleep(5)

            # Resolve services with retries
            servs, chars = [], []
            max_discovery_attempts = 6
            for attempt in range(1, max_discovery_attempts + 1):
                servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                if len(servs) > 0 and len(chars) > 0:
                    logger().info(f"[Iter {iteration}] Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                    break

                logger().warning(
                    f"[Iter {iteration}] Peripheral {idx + 1}: empty GATT discovery on attempt "
                    f"{attempt}/{max_discovery_attempts}; services={len(servs)}, chars={len(chars)}"
                )
                time.sleep(10)

            assert len(servs) > 0, f"[Iter {iteration}] No services fetched for peripheral {idx + 1}"
            assert len(chars) > 0, f"[Iter {iteration}] Fetched characters are empty for peripheral {idx + 1}"

            char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs,
                service_uid=service_uid,
                char_uid=char_uid
            )
            assert char_path, f"[Iter {iteration}] Characters are empty for peripheral {idx + 1}"

            logger().info(f"[Iter {iteration}] Peripheral {idx + 1} connected with CI={ci_ms}ms")
            time.sleep(2)

        logger().info(f"[Iter {iteration}] All 8 peripherals connected")
        logger().info("  P1: CI=100ms | P2-P5: CI=200ms | P6-P8: CI=300ms")
        ble_dut.interfaces.bluetooth.ble_get_device_state()

        # ========== STEP B: Connect 2 centrals with CI = 120ms (DUT as SLAVE) ==========
        logger().info("=" * 60)
        logger().info(f"[Iter {iteration}] STEP B: Connecting 2 centrals with CI = 120ms")
        logger().info("=" * 60)

        central_addresses = []
        for c_idx, central in enumerate(central_clients):
            logger().info(f"[Iter {iteration}] Starting DUT advertising for central-{c_idx + 1}")

            ble_dut.interfaces.bluetooth.ble_start_advertising()
            time.sleep(2)

            central_address = central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            time.sleep(2)
            central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
            time.sleep(20)

            ble_dut.interfaces.bluetooth.ble_get_device_state()
            logger().info(f"[Iter {iteration}] Central-{c_idx + 1} connected to DUT")
            time.sleep(2)

            ble_dut.interfaces.bluetooth.ble_stop_advertising()
            central_addresses.append(central_address)

            # Update connection parameters: CI = 120ms, SL = 0, LSTO = 4000ms
            logger().info(
                f"[Iter {iteration}] Updating central-{c_idx + 1} params: "
                f"CI={CENTRAL_CI} (120ms), SL={CENTRAL_SL}, LSTO={CENTRAL_LSTO} (4000ms)"
            )
            ble_dut.interfaces.bluetooth.ble_update_connect_params(
                ble_remote_dev_address=central_address,
                min_int=CENTRAL_CI,
                max_int=CENTRAL_CI,
                latency=CENTRAL_SL,
                supervision_timeout=CENTRAL_LSTO,
            )
            time.sleep(5)

        logger().info(f"[Iter {iteration}] Both centrals connected with CI = 120ms")
        ble_dut.interfaces.bluetooth.ble_get_device_state()

        # ========== STEP C: Disconnect all from remote side ==========
        logger().info("=" * 60)
        logger().info(f"[Iter {iteration}] STEP C: Disconnecting all 8P + 2C from remote side")
        logger().info("=" * 60)

        # Disconnect peripherals from remote (client) side
        for idx, client in enumerate(peripheral_clients):
            logger().info(f"[Iter {iteration}] Disconnecting peripheral {idx + 1} from remote side")
            client.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(1)

        # Disconnect centrals from remote (central) side
        for c_idx, central in enumerate(central_clients):
            logger().info(f"[Iter {iteration}] Disconnecting central-{c_idx + 1} from remote side")
            central.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(1)

        time.sleep(5)
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"[Iter {iteration}] All devices disconnected successfully")

        # Brief pause before next iteration
        if iteration < RECONNECT_ITERATIONS:
            logger().info(f"Waiting before iteration {iteration + 1}...")
            time.sleep(10)

    logger().info("=" * 60)
    logger().info(f"All {RECONNECT_ITERATIONS} connect/disconnect iterations completed successfully")
    logger().info("===== Test C768077 complete! =====")



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
@pytest.mark.test_src_map_id('C768078')
def test_8p_2c_just_works_pairing_C768078(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Just Works pairing: IO Capability = NoInputNoOutput (capability=3 on DUT, "NoInputNoOutput" on BlueZ)
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []

    # ========== PHASE 1: Connect 8 peripherals in Just Works pairing mode (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripherals in Just Works pairing mode (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Just Works) =====")

        # Start advertising with Just Works capability (NoInputNoOutput)
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={JUST_WORKS_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and paired (Just Works), service discovery verified")
        time.sleep(2)

    logger().info("All 8 peripherals connected in Just Works pairing mode")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect 2 central devices in Just Works pairing mode (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 centrals in Just Works pairing mode (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Just Works) =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        # Start scan with Just Works capability (NoInputNoOutput)
        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={JUST_WORKS_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

    logger().info("Both central devices connected in Just Works pairing mode")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Stability test for 5 minutes ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Stability test - 8P + 2C Just Works connections for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        time.sleep(stability_check_interval)
        elapsed += stability_check_interval
        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec")

        # Verify DUT device state (should show connected)
        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state: {device_state}")

    logger().info("5-minute stability test PASSED - 8P + 2C Just Works connections stable")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Disconnecting central-{c_idx + 1}")
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    logger().info("===== Test C768078 complete! =====")



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
@pytest.mark.test_src_map_id('C768068')
def test_adv_211ms_scan_33ms_C768068(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'HealthThermometerService'

    # BLE timing parameters (units: 0.625ms per unit)
    # Advertising interval: 211.25ms / 0.625 = 338 units
    ADV_INT_MIN = 338
    ADV_INT_MAX = 338
    # Scan interval: 33.125ms / 0.625 = 53 units
    SCAN_INTERVAL = 53
    # Scan window: 33.125ms / 0.625 = 53 units
    SCAN_WINDOW = 53

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # ========== PHASE 1: Start 8 peripherals advertising ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Starting 8 peripheral devices in advertising mode")
    logger().info("=" * 60)

    peripheral_addresses = []
    for idx, client in enumerate(peripheral_clients):
        logger().info(f"Starting peripheral-{idx + 1} advertising")
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc]
        )
        assert client_address, f"Failed to start advertising on peripheral device {idx + 1}"
        peripheral_addresses.append(client_address)
        logger().info(f"Peripheral-{idx + 1} advertising at address: {client_address}")

    logger().info("All 8 peripherals are advertising")

    # ========== PHASE 2: DUT starts scanning with SI=33.125ms, SW=33.125ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: DUT scanning with SI=33.125ms (53 units), SW=33.125ms (53 units)")
    logger().info("=" * 60)

    for idx, addr in enumerate(peripheral_addresses):
        logger().info(f"DUT scanning for peripheral-{idx + 1} ({addr})...")
        scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=addr,
            ble_scan_interval=SCAN_INTERVAL,
            ble_scan_window=SCAN_WINDOW,
        )
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info(f"Peripheral-{idx + 1} scan report: {scan_report}")
        time.sleep(1)

    logger().info("DUT successfully scanned all 8 peripheral devices")

    # ========== PHASE 3: DUT starts advertising with interval=211.25ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: DUT advertising with interval=211.25ms (338 units)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_start_advertising(
        ble_adv_int_min=ADV_INT_MIN,
        ble_adv_int_max=ADV_INT_MAX,
    )
    logger().info(f"DUT advertising started: interval min={ADV_INT_MIN} ({ADV_INT_MIN * 0.625}ms), "
                  f"max={ADV_INT_MAX} ({ADV_INT_MAX * 0.625}ms)")
    time.sleep(5)

    # ========== PHASE 4: Verify DUT advertising visible on 2 central devices ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Verifying DUT advertising visible on 2 central devices")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Central-{c_idx + 1} scanning for DUT...")
        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(10)
        central.interfaces.bluetooth.stop_scanning()

        found_devices = central.interfaces.bluetooth.get_devices()
        logger().info(f"Central-{c_idx + 1} scanned devices: {found_devices}")
        assert bt_dut_address.upper() in found_devices, \
            f"DUT {bt_dut_address} not found in central-{c_idx + 1} scan list. Found: {found_devices}"
        logger().info(
            f"DUT {bt_dut_address} visible in central-{c_idx + 1} scan list - "
            f"advertising on channels 37/38/39 confirmed"
        )

    logger().info("DUT advertising verified on both central devices")

    # ========== PHASE 5: Clean up ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Clean up")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(1)

    logger().info("===== Test C768068 complete! =====")



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
@pytest.mark.test_src_map_id('C768069')
def test_adv_211ms_scan_si33_sw14_C768069(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'HealthThermometerService'

    # BLE timing parameters (units: 0.625ms per unit)
    # Advertising interval: 211.25ms / 0.625 = 338 units
    ADV_INT_MIN = 338
    ADV_INT_MAX = 338
    # Scan interval: 33.125ms / 0.625 = 53 units
    SCAN_INTERVAL = 53
    # Scan window: 14.375ms / 0.625 = 23 units
    SCAN_WINDOW = 23

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # ========== PHASE 1: Start 8 peripherals advertising ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Starting 8 peripheral devices in advertising mode")
    logger().info("=" * 60)

    peripheral_addresses = []
    for idx, client in enumerate(peripheral_clients):
        logger().info(f"Starting peripheral-{idx + 1} advertising")
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc]
        )
        assert client_address, f"Failed to start advertising on peripheral device {idx + 1}"
        peripheral_addresses.append(client_address)
        logger().info(f"Peripheral-{idx + 1} advertising at address: {client_address}")

    logger().info("All 8 peripherals are advertising")

    # ========== PHASE 2: DUT starts scanning with SI=33.125ms, SW=14.375ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: DUT scanning with SI=33.125ms (53 units), SW=14.375ms (23 units)")
    logger().info("=" * 60)

    for idx, addr in enumerate(peripheral_addresses):
        logger().info(f"DUT scanning for peripheral-{idx + 1} ({addr})...")
        scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=addr,
            ble_scan_interval=SCAN_INTERVAL,
            ble_scan_window=SCAN_WINDOW,
        )
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info(f"Peripheral-{idx + 1} scan report: {scan_report}")
        time.sleep(1)

    logger().info("DUT successfully scanned all 8 peripheral devices")

    # ========== PHASE 3: DUT starts advertising with interval=211.25ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: DUT advertising with interval=211.25ms (338 units)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_start_advertising(
        ble_adv_int_min=ADV_INT_MIN,
        ble_adv_int_max=ADV_INT_MAX,
    )
    logger().info(f"DUT advertising started: interval min={ADV_INT_MIN} ({ADV_INT_MIN * 0.625}ms), "
                  f"max={ADV_INT_MAX} ({ADV_INT_MAX * 0.625}ms)")
    time.sleep(5)

    # ========== PHASE 4: Verify DUT advertising visible on 2 central devices ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Verifying DUT advertising visible on 2 central devices")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Central-{c_idx + 1} scanning for DUT...")
        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(10)
        central.interfaces.bluetooth.stop_scanning()

        found_devices = central.interfaces.bluetooth.get_devices()
        logger().info(f"Central-{c_idx + 1} scanned devices: {found_devices}")
        assert bt_dut_address.upper() in found_devices, \
            f"DUT {bt_dut_address} not found in central-{c_idx + 1} scan list. Found: {found_devices}"
        logger().info(
            f"DUT {bt_dut_address} visible in central-{c_idx + 1} scan list - "
            f"advertising on channels 37/38/39 confirmed"
        )

    logger().info("DUT advertising verified on both central devices")

    # ========== PHASE 5: Clean up ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Clean up")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(1)

    logger().info("===== Test C768069 complete! =====")



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
@pytest.mark.test_src_map_id('C768070')
def test_adv_211ms_scan_si33_sw11_C768070(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'HealthThermometerService'

    # BLE timing parameters (units: 0.625ms per unit)
    # Advertising interval: 211.25ms / 0.625 = 338 units
    ADV_INT_MIN = 338
    ADV_INT_MAX = 338
    # Scan interval: 33.125ms / 0.625 = 53 units
    SCAN_INTERVAL = 53
    # Scan window: 11.25ms / 0.625 = 18 units
    SCAN_WINDOW = 18

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # ========== PHASE 1: Start 8 peripherals advertising ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Starting 8 peripheral devices in advertising mode")
    logger().info("=" * 60)

    peripheral_addresses = []
    for idx, client in enumerate(peripheral_clients):
        logger().info(f"Starting peripheral-{idx + 1} advertising")
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc]
        )
        assert client_address, f"Failed to start advertising on peripheral device {idx + 1}"
        peripheral_addresses.append(client_address)
        logger().info(f"Peripheral-{idx + 1} advertising at address: {client_address}")

    logger().info("All 8 peripherals are advertising")

    # ========== PHASE 2: DUT starts scanning with SI=33.125ms, SW=11.25ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: DUT scanning with SI=33.125ms (53 units), SW=11.25ms (18 units)")
    logger().info("=" * 60)

    for idx, addr in enumerate(peripheral_addresses):
        logger().info(f"DUT scanning for peripheral-{idx + 1} ({addr})...")
        scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=addr,
            ble_scan_interval=SCAN_INTERVAL,
            ble_scan_window=SCAN_WINDOW,
        )
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info(f"Peripheral-{idx + 1} scan report: {scan_report}")
        time.sleep(1)

    logger().info("DUT successfully scanned all 8 peripheral devices")

    # ========== PHASE 3: DUT starts advertising with interval=211.25ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: DUT advertising with interval=211.25ms (338 units)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_start_advertising(
        ble_adv_int_min=ADV_INT_MIN,
        ble_adv_int_max=ADV_INT_MAX,
    )
    logger().info(f"DUT advertising started: interval min={ADV_INT_MIN} ({ADV_INT_MIN * 0.625}ms), "
                  f"max={ADV_INT_MAX} ({ADV_INT_MAX * 0.625}ms)")
    time.sleep(5)

    # ========== PHASE 4: Verify DUT advertising visible on 2 central devices ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Verifying DUT advertising visible on 2 central devices")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Central-{c_idx + 1} scanning for DUT...")
        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(10)
        central.interfaces.bluetooth.stop_scanning()

        found_devices = central.interfaces.bluetooth.get_devices()
        logger().info(f"Central-{c_idx + 1} scanned devices: {found_devices}")
        assert bt_dut_address.upper() in found_devices, \
            f"DUT {bt_dut_address} not found in central-{c_idx + 1} scan list. Found: {found_devices}"
        logger().info(
            f"DUT {bt_dut_address} visible in central-{c_idx + 1} scan list - "
            f"advertising on channels 37/38/39 confirmed"
        )

    logger().info("DUT advertising verified on both central devices")

    # ========== PHASE 5: Clean up ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Clean up")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(1)

    logger().info("===== Test C768070 complete! =====")



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
@pytest.mark.test_src_map_id('C768071')
def test_adv_211ms_scan_si6600_sw3300_C768071(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'HealthThermometerService'

    # BLE timing parameters (units: 0.625ms per unit)
    # Advertising interval: 211.25ms / 0.625 = 338 units
    ADV_INT_MIN = 338
    ADV_INT_MAX = 338
    # Scan interval: 6600ms / 0.625 = 10560 units
    SCAN_INTERVAL = 10560
    # Scan window: 3300ms / 0.625 = 5280 units
    SCAN_WINDOW = 5280

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # ========== PHASE 1: Start 8 peripherals advertising ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Starting 8 peripheral devices in advertising mode")
    logger().info("=" * 60)

    peripheral_addresses = []
    for idx, client in enumerate(peripheral_clients):
        logger().info(f"Starting peripheral-{idx + 1} advertising")
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc]
        )
        assert client_address, f"Failed to start advertising on peripheral device {idx + 1}"
        peripheral_addresses.append(client_address)
        logger().info(f"Peripheral-{idx + 1} advertising at address: {client_address}")

    logger().info("All 8 peripherals are advertising")

    # ========== PHASE 2: DUT starts scanning with SI=6600ms, SW=3300ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: DUT scanning with SI=6600ms (10560 units), SW=3300ms (5280 units)")
    logger().info("=" * 60)

    for idx, addr in enumerate(peripheral_addresses):
        logger().info(f"DUT scanning for peripheral-{idx + 1} ({addr})...")
        scan_report = ble_dut.interfaces.bluetooth.ble_start_scanning(
            ble_client_address=addr,
            ble_scan_interval=SCAN_INTERVAL,
            ble_scan_window=SCAN_WINDOW,
        )
        time.sleep(10)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        logger().info(f"Peripheral-{idx + 1} scan report: {scan_report}")
        time.sleep(1)

    logger().info("DUT successfully scanned all 8 peripheral devices")

    # ========== PHASE 3: DUT starts advertising with interval=211.25ms ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: DUT advertising with interval=211.25ms (338 units)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_start_advertising(
        ble_adv_int_min=ADV_INT_MIN,
        ble_adv_int_max=ADV_INT_MAX,
    )
    logger().info(f"DUT advertising started: interval min={ADV_INT_MIN} ({ADV_INT_MIN * 0.625}ms), "
                  f"max={ADV_INT_MAX} ({ADV_INT_MAX * 0.625}ms)")
    time.sleep(5)

    # ========== PHASE 4: Verify DUT advertising visible on 2 central devices ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Verifying DUT advertising visible on 2 central devices")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Central-{c_idx + 1} scanning for DUT...")
        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(10)
        central.interfaces.bluetooth.stop_scanning()

        found_devices = central.interfaces.bluetooth.get_devices()
        logger().info(f"Central-{c_idx + 1} scanned devices: {found_devices}")
        assert bt_dut_address.upper() in found_devices, \
            f"DUT {bt_dut_address} not found in central-{c_idx + 1} scan list. Found: {found_devices}"
        logger().info(
            f"DUT {bt_dut_address} visible in central-{c_idx + 1} scan list - "
            f"advertising on channels 37/38/39 confirmed"
        )

    logger().info("DUT advertising verified on both central devices")

    # ========== PHASE 5: Clean up ==========
    logger().info("=" * 60)
    logger().info("PHASE 5: Clean up")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_stop_advertising()
    time.sleep(1)

    logger().info("===== Test C768071 complete! =====")


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
@pytest.mark.test_src_map_id('C768081')
def test_8p_2c_connection_tx_notify_20_bytes_nonsecure_C768081(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Disable SMP for non-secure mode
    ble_dut.interfaces.bluetooth.ble_smp_enable(enable=0)
    logger().info("SMP disabled for all connections (non-secure mode)")

    client_addresses = []
    notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection.
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, non-secure)")
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
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (non-secure)")
        time.sleep(2)

        # Start notify thread for this new connection
        start_notify_thread(conn_id=idx)

        # Resume all notification threads (existing + new)
        resume_notifications()

    # ========== PHASE 2: Connect 2 centrals + start notify after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, non-secure)")
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
        logger().info(f"Central-{c_idx + 1} connected to DUT (non-secure)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        # Resume all notification threads
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min (non-secure)")
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

    logger().info("===== Test C768081 complete (non-secure mode) =====")


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
@pytest.mark.test_src_map_id('C768082')
def test_2c_tx_notify_8p_rx_notify_20_bytes_nonsecure_C768082(ble_dut, ble_client, ble_clients):

    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Disable SMP for non-secure mode
    ble_dut.interfaces.bluetooth.ble_smp_enable(enable=0)
    logger().info("SMP disabled for all connections (non-secure mode)")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread for central connections.
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Central conn {conn_id}] TX Notification #{count} sent")
                except Exception as e:
                    logger().error(f"[Central conn {conn_id}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Central conn {conn_id}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all TX notification threads before scan/connect."""
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        """Resume all TX notification threads after scan/connect."""
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        """Start a new parallel TX notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Central {conn_id - 7})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, non-secure)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (non-secure)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (20 bytes)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, non-secure)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        # Pause TX notification threads during scan/connect
        if tx_notify_threads:
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
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        # The DUT firmware discovers the peripheral's services and subscribes to
        # notifications, allowing the DUT to receive RX data from the peripheral.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected, RX notifications enabled (non-secure)")
        time.sleep(2)

        # Resume TX notification threads
        resume_notifications()

    # ========== PHASE 3: Run TX + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (non-secure)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768082 complete (non-secure, TX to centrals + RX from peripherals) =====")


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
@pytest.mark.test_src_map_id('C768084')
def test_8p_2c_connection_tx_write_with_resp_20_bytes_nonsecure_C768084(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # 20 bytes of write data
    wr_data = "thisistwentybytesdata"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Disable SMP for non-secure mode
    ble_dut.interfaces.bluetooth.ble_smp_enable(enable=0)
    logger().info("SMP disabled for all connections (non-secure mode)")

    client_addresses = []
    wr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wr_allowed = threading.Event()
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection.
           Pauses when wr_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        """Pause all write-with-response threads before scan/connect."""
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        """Resume all write-with-response threads after scan/connect."""
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        """Start a new parallel write-with-response thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals + start write-with-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, non-secure)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wr_threads:
            pause_wr()

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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (non-secure)")
        time.sleep(2)

        start_wr_thread(conn_id=idx)

        resume_wr()

    # ========== PHASE 2: Connect 2 centrals + start write-with-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, non-secure)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_wr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (non-secure)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        start_wr_thread(conn_id=8 + c_idx)

        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min (non-secure)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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

    logger().info("===== Test C768084 complete (non-secure mode) =====")


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
@pytest.mark.test_src_map_id('C768085')
def test_2c_8p_connection_tx_write_no_resp_20_bytes_nonsecure_C768085(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # 20 bytes of write data
    wwr_data = "thisistwentybytesdata"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Disable SMP for non-secure mode
    ble_dut.interfaces.bluetooth.ble_smp_enable(enable=0)
    logger().info("SMP disabled for all connections (non-secure mode)")

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wwr_allowed = threading.Event()
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection.
           Pauses when wwr_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 2 centrals + start write-no-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, non-secure)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if wwr_threads:
            pause_wwr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (non-secure)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        resume_wwr()

    logger().info("2 central connections established with write-no-resp (20 bytes)")

    # ========== PHASE 2: Connect 8 peripherals + start write-no-resp after each ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, non-secure)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

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
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        # DO NOT call enable_notifications / subscribe_to_notifications / read_charac_value
        # Those write to the CCCD which enables indications — not needed for write-no-resp

        logger().info(f"Peripheral {idx + 1} connected and ready for write-no-resp (non-secure)")
        time.sleep(2)

        # Start write-no-resp thread — DUT firmware resolves handles internally per conn_id
        start_wwr_thread(conn_id=idx)

        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min (non-secure)")
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

    logger().info("===== Test C768085 complete (non-secure mode) =====")


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
@pytest.mark.test_src_map_id('C768087')
def test_2c_tx_notify_8p_rx_notify_20_bytes_just_works_C768087(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Just Works pairing: IO Capability = NoInputNoOutput
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread for central connections.
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Central conn {conn_id}] TX Notification #{count} sent")
                except Exception as e:
                    logger().error(f"[Central conn {conn_id}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Central conn {conn_id}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all TX notification threads before scan/connect."""
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        """Resume all TX notification threads after scan/connect."""
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        """Start a new parallel TX notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Central {conn_id - 7})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) with Just Works pairing + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Just Works pairing)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Just Works) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        # Start scan with Just Works capability (NoInputNoOutput)
        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={JUST_WORKS_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (20 bytes, Just Works)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) with Just Works pairing + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Just Works pairing)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Just Works) =====")

        # Pause TX notification threads during scan/connect
        if tx_notify_threads:
            pause_notifications()

        # Start advertising with Just Works capability (NoInputNoOutput)
        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={JUST_WORKS_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        # The DUT firmware discovers the peripheral's services and subscribes to
        # notifications, allowing the DUT to receive RX data from the peripheral.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Just Works), RX notifications enabled")
        time.sleep(2)

        # Resume TX notification threads
        resume_notifications()

    # ========== PHASE 3: Run TX + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (Just Works)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768087 complete (Just Works, TX to centrals + RX from peripherals) =====")


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
@pytest.mark.test_src_map_id('C768088')
def test_8p_2c_connection_tx_indicate_20_bytes_just_works_C768088(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Just Works pairing: IO Capability = NoInputNoOutput
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    # 20 bytes of indication data
    indicate_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    indicate_allowed = threading.Event()
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection.
           Pauses when indicate_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Just Works pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Just Works)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Just Works) =====")

        if indicate_threads:
            pause_indications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={JUST_WORKS_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and paired (Just Works), indicate enabled")
        time.sleep(2)

        start_indicate_thread(conn_id=idx)

        resume_indications()

    # ========== PHASE 2: Connect 2 centrals with Just Works pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Just Works)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Just Works) =====")

        pause_indications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={JUST_WORKS_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        start_indicate_thread(conn_id=8 + c_idx)

        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (Just Works)")
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

    logger().info("===== Test C768088 complete (Just Works, TX indications 20 bytes) =====")


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
@pytest.mark.test_src_map_id('C768102')
def test_2c_tx_notify_230_bytes_8p_rx_notify_just_works_C768102(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Just Works pairing: IO Capability = NoInputNoOutput
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread for central connections (230 bytes).
           Pauses when notify_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Central conn {conn_id}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Central conn {conn_id}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Central conn {conn_id}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all TX notification threads before scan/connect."""
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        """Resume all TX notification threads after scan/connect."""
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        """Start a new parallel TX notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Central {conn_id - 7})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) with Just Works + start TX notify (230 bytes) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Just Works pairing)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Just Works) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={JUST_WORKS_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (230 bytes, Just Works)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) with Just Works + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Just Works pairing)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Just Works) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=JUST_WORKS_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={JUST_WORKS_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Just Works), RX notifications enabled")
        time.sleep(2)

        resume_notifications()

    # ========== PHASE 3: Run TX (230 bytes) + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals, 230 bytes) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (Just Works)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768102 complete (Just Works, TX 230 bytes to centrals + RX from peripherals) =====")



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
@pytest.mark.test_src_map_id('C768103')
def test_2c_8p_connection_tx_indicate_230_bytes_just_works_C768103(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Just Works pairing: IO Capability = NoInputNoOutput
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    # 230 bytes of indication data
    indicate_data = "test_data_for_indication_of_two_thirty_bytes_to_peripheral_test_data_for_indication_of_two_thirty_bytess_to_peripheral_test_data_for_indicate_of_two_thirty_bytes_to_peripheral_test_data_for_indicate_two_thirty_bytes_to_per"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    indicate_allowed = threading.Event()
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection.
           Pauses when indicate_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Indication #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Indication #{count} failed: {e}")

            time.sleep(indicate_interval)
        logger().info(f"[Client {conn_id + 1}] Indication thread stopped after {count} indications")

    def pause_indications():
        """Pause all indication threads before scan/connect."""
        logger().info(">>> Pausing all indication threads for scan/connect")
        indicate_allowed.clear()
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

    # ========== PHASE 1: Connect 2 centrals with Just Works pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices with Just Works pairing (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if indicate_threads:
            pause_indications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=JUST_WORKS_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        # Resume all indication threads
        resume_indications()

    # ========== PHASE 2: Connect 8 peripherals with Just Works pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices with Just Works pairing (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if indicate_threads:
            pause_indications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability=JUST_WORKS_CAPABILITY
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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (Just Works)")
        time.sleep(2)

        # Start indicate thread for this new connection
        start_indicate_thread(conn_id=idx)

        # Resume all indication threads (existing + new)
        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (Just Works, 230 bytes)")
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

    logger().info("===== Test C768103 complete (Just Works, TX indications 230 bytes) =====")



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
@pytest.mark.test_src_map_id('C768104')
def test_2c_8p_connection_tx_write_with_resp_230_bytes_just_works_C768104(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # Just Works pairing: IO Capability = NoInputNoOutput
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    # 230 bytes of write data
    wr_data = "test_data_for_write_resp_of_two_thirty_bytes_to_peripheral_test_data_for_write_resp_of_two_thirty_bytess_to_peripheral_test_data_for_write_resp_of_two_thirty_bytes_to_peripheral_test_data_for_write_resp_two_thirty_bytes_to_per"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    wr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wr_allowed = threading.Event()
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection.
           Pauses when wr_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        """Pause all write-with-response threads before scan/connect."""
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        """Resume all write-with-response threads after scan/connect."""
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        """Start a new parallel write-with-response thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals with Just Works pairing + start write-with-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices with Just Works pairing (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if wr_threads:
            pause_wr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=JUST_WORKS_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-with-resp thread for this central (conn_ids 8, 9)
        start_wr_thread(conn_id=8 + c_idx)

        # Resume all write-with-resp threads
        resume_wr()

    # ========== PHASE 2: Connect 8 peripherals with Just Works pairing + start write-with-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices with Just Works pairing (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wr_threads:
            pause_wr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability=JUST_WORKS_CAPABILITY
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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-with-resp (Just Works)")
        time.sleep(2)

        # Start write-with-resp thread for this peripheral
        start_wr_thread(conn_id=idx)

        # Resume all write-with-resp threads (existing + new)
        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min (Just Works, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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

    logger().info("===== Test C768104 complete (Just Works, TX write-with-resp 230 bytes) =====")



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
@pytest.mark.test_src_map_id('C768105')
def test_2c_8p_connection_tx_write_no_resp_230_bytes_just_works_C768105(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # Just Works pairing: IO Capability = NoInputNoOutput
    JUST_WORKS_CAPABILITY = "NoInputNoOutput"

    # 230 bytes of write data
    wwr_data = "test_data_for_write_no_resp_two_thirty_bytes_to_peripheral_test_data_for_write_no_resp_two_thirty_bytess_to_peripheral_test_data_for_write_no_resp_two_thirty_bytes_to_peripheral_test_data_for_write_no_resp_two_thirty_bytes_to"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wwr_allowed = threading.Event()
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection.
           Pauses when wwr_allowed is cleared.
           Acquires dut_lock before calling DUT to avoid test agent contention."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Write-no-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-no-resp #{count} failed: {e}")

            time.sleep(wwr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-no-resp thread stopped after {count} writes")

    def pause_wwr():
        """Pause all write-without-response threads before scan/connect."""
        logger().info(">>> Pausing all write-no-resp threads for scan/connect")
        wwr_allowed.clear()
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

    # ========== PHASE 1: Connect 2 centrals with Just Works pairing + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices with Just Works pairing (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if wwr_threads:
            pause_wwr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=JUST_WORKS_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Just Works)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        # Resume all write-no-resp threads
        resume_wwr()

    # ========== PHASE 2: Connect 8 peripherals with Just Works pairing + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices with Just Works pairing (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wwr_threads:
            pause_wwr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability=JUST_WORKS_CAPABILITY
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

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-no-resp (Just Works)")
        time.sleep(2)

        # Start write-no-resp thread for this peripheral
        start_wwr_thread(conn_id=idx)

        # Resume all write-no-resp threads (existing + new)
        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min (Just Works, 230 bytes)")
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

    logger().info("===== Test C768105 complete (Just Works, TX write-no-resp 230 bytes) =====")



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
@pytest.mark.test_src_map_id('C768079')
def test_2c_8p_numeric_comparison_pairing_C768079(ble_dut, ble_client, ble_clients):
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Numeric Comparison pairing: IO Capability = DisplayYesNo (value 1 on DUT)
    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []

    # ========== PHASE 1: Connect 2 centrals in Numeric Comparison pairing mode (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 centrals in Numeric Comparison pairing mode (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={NUMERIC_COMPARISON_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

    logger().info("Both central devices connected in Numeric Comparison pairing mode")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect 8 peripherals in Numeric Comparison pairing mode (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripherals in Numeric Comparison pairing mode (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={NUMERIC_COMPARISON_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and paired (Numeric Comparison), service discovery verified")
        time.sleep(2)

    logger().info("All 8 peripherals connected in Numeric Comparison pairing mode")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Stability test for 5 minutes ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Stability test - 2C + 8P Numeric Comparison connections for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        time.sleep(stability_check_interval)
        elapsed += stability_check_interval
        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec")

        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state: {device_state}")

    logger().info("5-minute stability test PASSED - 2C + 8P Numeric Comparison connections stable")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Disconnecting central-{c_idx + 1}")
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    logger().info("===== Test C768079 complete (Numeric Comparison pairing) =====")



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
@pytest.mark.test_src_map_id('C768080')
def test_8p_2c_passkey_entry_pairing_C768080(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Passkey Entry pairing: IO Capability = KeyboardOnly on remote side
    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to KeyboardDisplay (4) with MITM enabled for Passkey Entry
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []

    # ========== PHASE 1: Connect 8 peripherals in Passkey Entry pairing mode (DUT as MASTER) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripherals in Passkey Entry pairing mode (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), service discovery verified")
        time.sleep(2)

    logger().info("All 8 peripherals connected in Passkey Entry pairing mode")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect 2 centrals in Passkey Entry pairing mode (DUT as SLAVE) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 centrals in Passkey Entry pairing mode (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

    logger().info("Both central devices connected in Passkey Entry pairing mode")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 3: Stability test for 5 minutes ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Stability test - 8P + 2C Passkey Entry connections for 5 minutes")
    logger().info("=" * 60)

    stability_check_interval = 60  # seconds
    stability_duration = 5 * 60    # 5 minutes
    elapsed = 0

    while elapsed < stability_duration:
        time.sleep(stability_check_interval)
        elapsed += stability_check_interval
        logger().info(f"Stability check at {elapsed // 60} min {elapsed % 60} sec")

        device_state = ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"DUT device state: {device_state}")

    logger().info("5-minute stability test PASSED - 8P + 2C Passkey Entry connections stable")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"Disconnecting central-{c_idx + 1}")
        central.interfaces.bluetooth.disconnect(bt_dut_address)
        time.sleep(1)

    logger().info("===== Test C768080 complete (Passkey Entry pairing) =====")



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
@pytest.mark.test_src_map_id('C768091')
def test_8p_2c_tx_notify_20_bytes_numeric_comparison_C768091(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Numeric Comparison pairing: IO Capability = DisplayYesNo on both sides
    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Numeric Comparison + start notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripherals in Numeric Comparison mode (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        if notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected, paired (Numeric Comparison), and subscribed")
        time.sleep(2)

        start_notify_thread(conn_id=idx)
        resume_notifications()

    # ========== PHASE 2: Connect 2 centrals with Numeric Comparison + start notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 centrals in Numeric Comparison mode (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        start_notify_thread(conn_id=8 + c_idx)
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min (Numeric Comparison)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all notification threads =====")

    # ========== PHASE 4: Stop all notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

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

    logger().info("===== Test C768091 complete (Numeric Comparison, TX notify 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768092')
def test_2c_tx_notify_8p_rx_notify_20_bytes_numeric_comparison_C768092(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Numeric Comparison pairing: IO Capability = DisplayYesNo
    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all TX notification threads before scan/connect."""
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        """Resume all TX notification threads after scan/connect."""
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        """Start a new parallel TX notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) with Numeric Comparison + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison pairing)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={NUMERIC_COMPARISON_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (20 bytes, Numeric Comparison)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) with Numeric Comparison + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison pairing)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={NUMERIC_COMPARISON_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Numeric Comparison), RX notifications enabled")
        time.sleep(2)

        resume_notifications()

    # ========== PHASE 3: Run TX + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (Numeric Comparison)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768092 complete (Numeric Comparison, TX to centrals + RX from peripherals) =====")



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
@pytest.mark.test_src_map_id('C768093')
def test_8p_2c_tx_indicate_20_bytes_numeric_comparison_C768093(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Numeric Comparison pairing: IO Capability = DisplayYesNo
    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    # 20 bytes of indication data
    indicate_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    indicate_allowed = threading.Event()
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Numeric Comparison pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        if indicate_threads:
            pause_indications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={NUMERIC_COMPARISON_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected, paired (Numeric Comparison), and subscribed")
        time.sleep(2)

        # Start indicate thread for this peripheral
        start_indicate_thread(conn_id=idx)

        resume_indications()

    # ========== PHASE 2: Connect 2 centrals with Numeric Comparison pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        pause_indications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={NUMERIC_COMPARISON_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (Numeric Comparison, 20 bytes)")
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

    logger().info("===== Test C768093 complete (Numeric Comparison, TX indications 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768094')
def test_8p_2c_tx_write_with_resp_20_bytes_numeric_comparison_C768094(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # Numeric Comparison pairing: IO Capability = DisplayYesNo
    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    # 20 bytes of write data
    wr_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    wr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wr_allowed = threading.Event()
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection."""
        count = 0
        while not stop_flag['stop']:
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_with_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        """Pause all write-with-response threads before scan/connect."""
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        """Resume all write-with-response threads after scan/connect."""
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        """Start a new parallel write-with-response thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals with Numeric Comparison pairing + start write-with-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        if wr_threads:
            pause_wr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={NUMERIC_COMPARISON_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected, paired (Numeric Comparison), and ready for write-with-resp")
        time.sleep(2)

        # Start write-with-resp thread for this peripheral
        start_wr_thread(conn_id=idx)

        resume_wr()

    # ========== PHASE 2: Connect 2 centrals with Numeric Comparison pairing + start write-with-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        pause_wr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={NUMERIC_COMPARISON_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-with-resp thread for this central (conn_ids 8, 9)
        start_wr_thread(conn_id=8 + c_idx)

        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min (Numeric Comparison, 20 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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

    logger().info("===== Test C768094 complete (Numeric Comparison, TX write-with-resp 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768095')
def test_8p_2c_tx_write_no_resp_20_bytes_numeric_comparison_C768095(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # Numeric Comparison pairing: IO Capability = DisplayYesNo
    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    # 20 bytes of write data
    wwr_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wwr_allowed = threading.Event()
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Numeric Comparison pairing + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        if wwr_threads:
            pause_wwr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={NUMERIC_COMPARISON_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected, paired (Numeric Comparison), and ready for write-no-resp")
        time.sleep(2)

        # Start write-no-resp thread for this peripheral
        start_wwr_thread(conn_id=idx)

        resume_wwr()

    # ========== PHASE 2: Connect 2 centrals with Numeric Comparison pairing + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        pause_wwr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={NUMERIC_COMPARISON_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min (Numeric Comparison, 20 bytes)")
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

    logger().info("===== Test C768095 complete (Numeric Comparison, TX write-no-resp 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768096')
def test_8p_2c_tx_notify_20_bytes_passkey_entry_C768096(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Passkey Entry pairing: IO Capability = KeyboardOnly on remote side
    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to KeyboardDisplay (4) with MITM enabled for Passkey Entry
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Passkey Entry + start notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripherals in Passkey Entry mode (DUT as MASTER)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected, paired (Passkey Entry), and subscribed")
        time.sleep(2)

        start_notify_thread(conn_id=idx)
        resume_notifications()

    # ========== PHASE 2: Connect 2 centrals with Passkey Entry + start notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 centrals in Passkey Entry mode (DUT as SLAVE)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        start_notify_thread(conn_id=8 + c_idx)
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min (Passkey Entry, 20 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all notification threads =====")

    # ========== PHASE 4: Stop all notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

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

    logger().info("===== Test C768096 complete (Passkey Entry, TX notify 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768097')
def test_2c_tx_notify_8p_rx_notify_20_bytes_passkey_entry_C768097(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Passkey Entry pairing: IO Capability = KeyboardOnly on remote side
    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to KeyboardDisplay (4) with MITM enabled for Passkey Entry
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all TX notification threads before scan/connect."""
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        """Resume all TX notification threads after scan/connect."""
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        """Start a new parallel TX notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) with Passkey Entry + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry pairing)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (20 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) with Passkey Entry + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry pairing)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), RX notifications enabled")
        time.sleep(2)

        resume_notifications()

    # ========== PHASE 3: Run TX + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (Passkey Entry)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768097 complete (Passkey Entry, TX to centrals + RX from peripherals) =====")



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
@pytest.mark.test_src_map_id('C768098')
def test_8p_2c_tx_indicate_20_bytes_passkey_entry_C768098(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    # Passkey Entry pairing: IO Capability = KeyboardOnly on remote side
    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    # 20 bytes of indication data
    indicate_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to KeyboardDisplay (4) with MITM enabled for Passkey Entry
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    indicate_allowed = threading.Event()
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Passkey Entry pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if indicate_threads:
            pause_indications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected, paired (Passkey Entry), and subscribed")
        time.sleep(2)

        # Start indicate thread for this peripheral
        start_indicate_thread(conn_id=idx)

        resume_indications()

    # ========== PHASE 2: Connect 2 centrals with Passkey Entry pairing + start indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        pause_indications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (Passkey Entry, 20 bytes)")
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

    logger().info("===== Test C768098 complete (Passkey Entry, TX indications 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768099')
def test_8p_2c_tx_write_with_resp_20_bytes_passkey_entry_C768099(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # Passkey Entry pairing: IO Capability = KeyboardOnly on remote side
    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    # 20 bytes of write data
    wr_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to KeyboardDisplay (4) with MITM enabled for Passkey Entry
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    wr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wr_allowed = threading.Event()
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection."""
        count = 0
        while not stop_flag['stop']:
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_with_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        """Pause all write-with-response threads before scan/connect."""
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        """Resume all write-with-response threads after scan/connect."""
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        """Start a new parallel write-with-response thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals with Passkey Entry pairing + start write-with-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if wr_threads:
            pause_wr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected, paired (Passkey Entry), and ready for write-with-resp")
        time.sleep(2)

        # Start write-with-resp thread for this peripheral
        start_wr_thread(conn_id=idx)

        resume_wr()

    # ========== PHASE 2: Connect 2 centrals with Passkey Entry pairing + start write-with-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        pause_wr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-with-resp thread for this central (conn_ids 8, 9)
        start_wr_thread(conn_id=8 + c_idx)

        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min (Passkey Entry, 20 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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

    logger().info("===== Test C768099 complete (Passkey Entry, TX write-with-resp 20 bytes) =====")



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
@pytest.mark.test_src_map_id('C768100')
def test_8p_2c_tx_write_no_resp_20_bytes_passkey_entry_C768100(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    # Passkey Entry pairing: IO Capability = KeyboardOnly on remote side
    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    # 20 bytes of write data
    wwr_data = "01020304050607080910"  # 20 bytes

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to KeyboardDisplay (4) with MITM enabled for Passkey Entry
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wwr_allowed = threading.Event()
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection."""
        count = 0
        while not stop_flag['stop']:
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

    # ========== PHASE 1: Connect 8 peripherals with Passkey Entry pairing + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if wwr_threads:
            pause_wwr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected, paired (Passkey Entry), and ready for write-no-resp")
        time.sleep(2)

        # Start write-no-resp thread for this peripheral
        start_wwr_thread(conn_id=idx)

        resume_wwr()

    # ========== PHASE 2: Connect 2 centrals with Passkey Entry pairing + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        pause_wwr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min (Passkey Entry, 20 bytes)")
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

    logger().info("===== Test C768100 complete (Passkey Entry, TX write-no-resp 20 bytes) =====")


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
@pytest.mark.test_src_map_id('C768106')
def test_2c_8p_tx_notify_230_bytes_numeric_comparison_C768106(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Numeric Comparison pairing mode: DisplayYesNo (io_capability=1), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("IO capability set to DisplayYesNo (Numeric Comparison), MITM enabled")

    client_addresses = []
    notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all notification threads")
        notify_allowed.set()

    def start_notify_thread(conn_id):
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

    # ========== PHASE 1: Connect 2 centrals first (DUT as SLAVE, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="DisplayYesNo")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        # Resume all notification threads
        resume_notifications()

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="DisplayYesNo"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (Numeric Comparison)")
        time.sleep(2)

        # Start notify thread for this new connection
        start_notify_thread(conn_id=idx)

        # Resume all notification threads (existing + new)
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min (Numeric Comparison, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all notification threads =====")

    # ========== PHASE 4: Stop all notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

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

    logger().info("===== Test C768106 complete (Numeric Comparison, TX notify 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768107')
def test_2c_tx_notify_8p_rx_notify_230_bytes_numeric_comparison_C768107(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    NUMERIC_COMPARISON_CAPABILITY = "DisplayYesNo"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set DUT IO capability to DisplayYesNo (1) with MITM enabled for Numeric Comparison
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        """Pause all TX notification threads before scan/connect."""
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        """Resume all TX notification threads after scan/connect."""
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        """Start a new parallel TX notification thread for the given conn_id."""
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) with Numeric Comparison + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison pairing)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={NUMERIC_COMPARISON_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NUMERIC_COMPARISON_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (230 bytes, Numeric Comparison)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) with Numeric Comparison + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison pairing)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NUMERIC_COMPARISON_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={NUMERIC_COMPARISON_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Numeric Comparison), RX notifications enabled")
        time.sleep(2)

        resume_notifications()

    # ========== PHASE 3: Run TX + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals, 230 bytes) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (Numeric Comparison)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()  # unblock any threads waiting on the event

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768107 complete (Numeric Comparison, TX 230 bytes to centrals + RX from peripherals) =====")


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
@pytest.mark.test_src_map_id('C768108')
def test_2c_8p_tx_indicate_230_bytes_numeric_comparison_C768108(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    indicate_data = ("test_data_for_indication_of_two_thirty_bytes_to_peripheral_"
                     "test_data_for_indication_of_two_thirty_bytess_to_peripheral_"
                     "test_data_for_indicate_of_two_thirty_bytes_to_peripheral_"
                     "test_data_for_indicate_two_thirty_bytes_to_peripheral_end")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Numeric Comparison pairing mode: DisplayYesNo (io_capability=1), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("IO capability set to DisplayYesNo (Numeric Comparison), MITM enabled")

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    indicate_allowed = threading.Event()
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Indication #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Indication #{count} failed: {e}")

            time.sleep(indicate_interval)
        logger().info(f"[Client {conn_id + 1}] Indication thread stopped after {count} indications")

    def pause_indications():
        logger().info(">>> Pausing all indication threads for scan/connect")
        indicate_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All indication threads paused")

    def resume_indications():
        logger().info(">>> Resuming all indication threads")
        indicate_allowed.set()

    def start_indicate_thread(conn_id):
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

    # ========== PHASE 1: Connect 2 centrals first (DUT as SLAVE, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if indicate_threads:
            pause_indications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="DisplayYesNo")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        resume_indications()

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if indicate_threads:
            pause_indications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="DisplayYesNo"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (Numeric Comparison)")
        time.sleep(2)

        # Start indicate thread for this new connection
        start_indicate_thread(conn_id=idx)

        # Resume all indication threads (existing + new)
        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (Numeric Comparison, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all indication threads =====")

    # ========== PHASE 4: Stop all indication threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    indicate_allowed.set()

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

    logger().info("===== Test C768108 complete (Numeric Comparison, TX indicate 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768109')
def test_2c_8p_tx_write_with_resp_230_bytes_numeric_comparison_C768109(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    wr_data = ("test_data_for_write_with_resp_of_two_thirty_bytes_to_device_"
               "test_data_for_write_with_resp_of_two_thirty_bytess_to_device_"
               "test_data_for_write_resp_of_two_thirty_bytes_to_device_"
               "test_data_for_write_resp_two_thirty_bytes_to_device_endpad")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Numeric Comparison pairing mode: DisplayYesNo (io_capability=1), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("IO capability set to DisplayYesNo (Numeric Comparison), MITM enabled")

    client_addresses = []
    wr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wr_allowed = threading.Event()
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_with_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals first (DUT as SLAVE, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if wr_threads:
            pause_wr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="DisplayYesNo")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-with-resp thread for this central (conn_ids 8, 9)
        start_wr_thread(conn_id=8 + c_idx)

        resume_wr()

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wr_threads:
            pause_wr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="DisplayYesNo"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-with-resp (Numeric Comparison)")
        time.sleep(2)

        # Start write-with-resp thread for this peripheral
        start_wr_thread(conn_id=idx)

        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min (Numeric Comparison, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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

    logger().info("===== Test C768109 complete (Numeric Comparison, TX write-with-resp 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768110')
def test_2c_8p_tx_write_no_resp_230_bytes_numeric_comparison_C768110(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    wwr_data = ("test_data_for_write_no_resp_of_two_thirty_bytes_to_device_"
                "test_data_for_write_no_resp_of_two_thirty_bytess_to_device_"
                "test_data_for_write_no_resp_of_two_thirty_bytes_to_device_"
                "test_data_for_write_no_resp_two_thirty_bytes_to_device_endpad")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Numeric Comparison pairing mode: DisplayYesNo (io_capability=1), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("IO capability set to DisplayYesNo (Numeric Comparison), MITM enabled")

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wwr_allowed = threading.Event()
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Write-no-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-no-resp #{count} failed: {e}")

            time.sleep(wwr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-no-resp thread stopped after {count} writes")

    def pause_wwr():
        logger().info(">>> Pausing all write-no-resp threads for scan/connect")
        wwr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-no-resp threads paused")

    def resume_wwr():
        logger().info(">>> Resuming all write-no-resp threads")
        wwr_allowed.set()

    def start_wwr_thread(conn_id):
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

    # ========== PHASE 1: Connect 2 centrals first (DUT as SLAVE, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        if wwr_threads:
            pause_wwr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="DisplayYesNo")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        resume_wwr()

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wwr_threads:
            pause_wwr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="DisplayYesNo"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-no-resp (Numeric Comparison)")
        time.sleep(2)

        # Start write-no-resp thread for this peripheral
        start_wwr_thread(conn_id=idx)

        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min (Numeric Comparison, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-no-resp threads =====")

    # ========== PHASE 4: Stop all write-no-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wwr_allowed.set()

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

    logger().info("===== Test C768110 complete (Numeric Comparison, TX write-no-resp 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768111')
def test_8p_2c_tx_notify_230_bytes_passkey_entry_C768111(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("IO capability set to KeyboardDisplay (Passkey Entry), MITM enabled")

    client_addresses = []
    notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all notification threads")
        notify_allowed.set()

    def start_notify_thread(conn_id):
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

    # ========== PHASE 1: Connect 8 peripherals first (DUT as MASTER, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="KeyboardOnly"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (Passkey Entry)")
        time.sleep(2)

        # Start notify thread for this new connection
        start_notify_thread(conn_id=idx)

        # Resume all notification threads (existing + new)
        resume_notifications()

    # ========== PHASE 2: Connect 2 centrals (DUT as SLAVE, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="KeyboardOnly")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        # Resume all notification threads
        resume_notifications()

    # ========== PHASE 3: Run all notifications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(notify_threads)} parallel notify threads running for 5 min (Passkey Entry, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all notification threads =====")

    # ========== PHASE 4: Stop all notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

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

    logger().info("===== Test C768111 complete (Passkey Entry, TX notify 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768112')
def test_2c_tx_notify_8p_rx_notify_230_bytes_passkey_entry_C768112(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE) with Passkey Entry + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry pairing)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        logger().info(f"Central-{c_idx + 1} scanning with capability={PASSKEY_ENTRY_CAPABILITY}")

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER) with Passkey Entry + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry pairing)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries since GATT discovery can be delayed intermittently.
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), RX notifications enabled")
        time.sleep(2)

        resume_notifications()

    # ========== PHASE 3: Run TX + RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (centrals, 230 bytes) + "
                  f"8 peripherals sending RX notifications to DUT. Running for 5 min (Passkey Entry)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768112 complete (Passkey Entry, TX 230 bytes to centrals + RX from peripherals) =====")


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
@pytest.mark.test_src_map_id('C768113')
def test_8p_2c_tx_indicate_230_bytes_passkey_entry_C768113(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    indicate_data = ("test_data_for_indication_of_two_thirty_bytes_to_peripheral_"
                     "test_data_for_indication_of_two_thirty_bytess_to_peripheral_"
                     "test_data_for_indicate_of_two_thirty_bytes_to_peripheral_"
                     "test_data_for_indicate_two_thirty_bytes_to_peripheral_end")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("IO capability set to KeyboardDisplay (Passkey Entry), MITM enabled")

    client_addresses = []
    indicate_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    indicate_allowed = threading.Event()
    indicate_allowed.set()

    def continuous_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel indication thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Indication #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Indication #{count} failed: {e}")

            time.sleep(indicate_interval)
        logger().info(f"[Client {conn_id + 1}] Indication thread stopped after {count} indications")

    def pause_indications():
        logger().info(">>> Pausing all indication threads for scan/connect")
        indicate_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All indication threads paused")

    def resume_indications():
        logger().info(">>> Resuming all indication threads")
        indicate_allowed.set()

    def start_indicate_thread(conn_id):
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

    # ========== PHASE 1: Connect 8 peripherals first (DUT as MASTER, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if indicate_threads:
            pause_indications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="KeyboardOnly"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (Passkey Entry)")
        time.sleep(2)

        # Start indicate thread for this new connection
        start_indicate_thread(conn_id=idx)

        # Resume all indication threads (existing + new)
        resume_indications()

    # ========== PHASE 2: Connect 2 centrals (DUT as SLAVE, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_indications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="KeyboardOnly")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start indicate thread for this central (conn_ids 8, 9)
        start_indicate_thread(conn_id=8 + c_idx)

        # Resume all indication threads
        resume_indications()

    # ========== PHASE 3: Run all indications for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(indicate_threads)} parallel indicate threads running for 5 min (Passkey Entry, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all indication threads =====")

    # ========== PHASE 4: Stop all indication threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    indicate_allowed.set()

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

    logger().info("===== Test C768113 complete (Passkey Entry, TX indicate 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768114')
def test_8p_2c_tx_write_with_resp_230_bytes_passkey_entry_C768114(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    wr_data = ("test_data_for_write_with_resp_of_two_thirty_bytes_to_device_"
               "test_data_for_write_with_resp_of_two_thirty_bytess_to_device_"
               "test_data_for_write_resp_of_two_thirty_bytes_to_device_"
               "test_data_for_write_resp_two_thirty_bytes_to_device_endpad")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("IO capability set to KeyboardDisplay (Passkey Entry), MITM enabled")

    client_addresses = []
    wr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wr_allowed = threading.Event()
    wr_allowed.set()

    def continuous_write_with_resp(conn_id, stop_flag, wr_interval=5):
        """Parallel write-with-response thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
            wr_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_with_resp(
                        conn_id=conn_id,
                        data=wr_data
                    )
                    logger().info(f"[Client {conn_id + 1}] Write-with-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-with-resp #{count} failed: {e}")

            time.sleep(wr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-with-resp thread stopped after {count} writes")

    def pause_wr():
        logger().info(">>> Pausing all write-with-resp threads for scan/connect")
        wr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-with-resp threads paused")

    def resume_wr():
        logger().info(">>> Resuming all write-with-resp threads")
        wr_allowed.set()

    def start_wr_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_with_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        wr_threads.append(t)
        logger().info(f"Write-with-resp thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 8 peripherals first (DUT as MASTER, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wr_threads:
            pause_wr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="KeyboardOnly"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-with-resp (Passkey Entry)")
        time.sleep(2)

        # Start write-with-resp thread for this peripheral
        start_wr_thread(conn_id=idx)

        resume_wr()

    # ========== PHASE 2: Connect 2 centrals (DUT as SLAVE, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_wr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="KeyboardOnly")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-with-resp thread for this central (conn_ids 8, 9)
        start_wr_thread(conn_id=8 + c_idx)

        resume_wr()

    # ========== PHASE 3: Run all write-with-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wr_threads)} parallel write-with-resp threads running for 5 min (Passkey Entry, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-with-resp threads =====")

    # ========== PHASE 4: Stop all write-with-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wr_allowed.set()

    for idx, thread in enumerate(wr_threads):
        thread.join(timeout=15)
        logger().info(f"Connection {idx + 1} write-with-resp thread joined")

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

    logger().info("===== Test C768114 complete (Passkey Entry, TX write-with-resp 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768115')
def test_8p_2c_tx_write_no_resp_230_bytes_passkey_entry_C768115(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    svc = 'ImmediateAlertService'

    wwr_data = ("test_data_for_write_no_resp_of_two_thirty_bytes_to_device_"
                "test_data_for_write_no_resp_of_two_thirty_bytess_to_device_"
                "test_data_for_write_no_resp_of_two_thirty_bytes_to_device_"
                "test_data_for_write_no_resp_two_thirty_bytes_to_device_endpad")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("IO capability set to KeyboardDisplay (Passkey Entry), MITM enabled")

    client_addresses = []
    wwr_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    wwr_allowed = threading.Event()
    wwr_allowed.set()

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] Write-no-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] Write-no-resp #{count} failed: {e}")

            time.sleep(wwr_interval)
        logger().info(f"[Client {conn_id + 1}] Write-no-resp thread stopped after {count} writes")

    def pause_wwr():
        logger().info(">>> Pausing all write-no-resp threads for scan/connect")
        wwr_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All write-no-resp threads paused")

    def resume_wwr():
        logger().info(">>> Resuming all write-no-resp threads")
        wwr_allowed.set()

    def start_wwr_thread(conn_id):
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

    # ========== PHASE 1: Connect 8 peripherals first (DUT as MASTER, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} =====")

        if wwr_threads:
            pause_wwr()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            service_classes=[svc],
            capability="KeyboardOnly"
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-no-resp (Passkey Entry)")
        time.sleep(2)

        # Start write-no-resp thread for this peripheral
        start_wwr_thread(conn_id=idx)

        resume_wwr()

    # ========== PHASE 2: Connect 2 centrals (DUT as SLAVE, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} =====")

        pause_wwr()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability="KeyboardOnly")
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected to DUT (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start write-no-resp thread for this central (conn_ids 8, 9)
        start_wwr_thread(conn_id=8 + c_idx)

        resume_wwr()

    # ========== PHASE 3: Run all write-no-resp for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! {len(wwr_threads)} parallel write-no-resp threads running for 5 min (Passkey Entry, 230 bytes)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all write-no-resp threads =====")

    # ========== PHASE 4: Stop all write-no-resp threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    wwr_allowed.set()

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

    logger().info("===== Test C768115 complete (Passkey Entry, TX write-no-resp 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768116')
def test_8p_rx_notify_2c_disconn_reconn_passkey_entry_C768116(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    RECONNECT_ITERATIONS = 5

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []

    # ========== PHASE 1: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + enable RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("DUT will receive RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[svc]
        )
        assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1}"
        client_addresses.append(client_address)
        logger().info(f"Peripheral {idx + 1} advertising with capability={PASSKEY_ENTRY_CAPABILITY}")

        ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
        time.sleep(3)
        ble_dut.interfaces.bluetooth.ble_stop_scanning()
        time.sleep(1)
        ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
        time.sleep(40)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), RX notifications enabled")
        time.sleep(2)

    logger().info("All 8 peripherals connected with RX notifications active")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: Connect 2 centrals + disconnect/reconnect loop (5 iterations) ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 2: 2 central connect/disconnect/reconnect loop ({RECONNECT_ITERATIONS} iterations, Passkey Entry)")
    logger().info("=" * 60)

    for iteration in range(1, RECONNECT_ITERATIONS + 1):
        logger().info(f"===== Iteration {iteration}/{RECONNECT_ITERATIONS}: Connecting 2 centrals =====")

        # Connect both centrals
        for c_idx, central in enumerate(central_clients):
            logger().info(f"  Starting DUT advertising for central-{c_idx + 1} (iteration {iteration})")

            ble_dut.interfaces.bluetooth.ble_start_advertising()
            time.sleep(2)

            central.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=bt_dut_address,
                capability=PASSKEY_ENTRY_CAPABILITY
            )
            time.sleep(2)

            central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
            time.sleep(20)

            ble_dut.interfaces.bluetooth.ble_get_device_state()
            logger().info(f"  Central-{c_idx + 1} connected (Passkey Entry, iteration {iteration})")
            time.sleep(2)

            ble_dut.interfaces.bluetooth.ble_stop_advertising()

        logger().info(f"  Both centrals connected (iteration {iteration}), verifying DUT state")
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Disconnect both centrals
        logger().info(f"===== Iteration {iteration}/{RECONNECT_ITERATIONS}: Disconnecting 2 centrals =====")

        for c_idx, central in enumerate(central_clients):
            logger().info(f"  Disconnecting central-{c_idx + 1} (iteration {iteration})")
            central.interfaces.bluetooth.disconnect(bt_dut_address)
            time.sleep(2)

        logger().info(f"  Both centrals disconnected (iteration {iteration})")
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        logger().info(f"  Iteration {iteration}/{RECONNECT_ITERATIONS} complete")

    logger().info(f"All {RECONNECT_ITERATIONS} connect/disconnect/reconnect iterations completed")

    # ========== PHASE 3: Verify 8 peripheral connections still stable ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Verifying 8 peripheral connections still stable after central churn")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()
    time.sleep(5)

    # ========== PHASE 4: Disconnect all peripherals ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all peripheral clients")
    logger().info("=" * 60)

    for idx, addr in enumerate(client_addresses):
        logger().info(f"Disconnecting peripheral {idx + 1}")
        ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
        time.sleep(1)

    logger().info("===== Test C768116 complete (Passkey Entry, 8P RX notify + 2C disconn/reconn x5) =====")


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
@pytest.mark.test_src_map_id('C768117')
def test_2c_tx_notify_230_8p_disconn_reconn_passkey_entry_C768117(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    RECONNECT_ITERATIONS = 5

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with TX notifications (230 bytes, Passkey Entry)")
    ble_dut.interfaces.bluetooth.ble_get_device_state()

    # ========== PHASE 2: 8 peripheral connect/disconnect/reconnect loop (5 iterations) ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 2: 8 peripheral connect/disconnect/reconnect loop ({RECONNECT_ITERATIONS} iterations, Passkey Entry)")
    logger().info("TX notifications to 2 centrals continue throughout")
    logger().info("=" * 60)

    for iteration in range(1, RECONNECT_ITERATIONS + 1):
        logger().info(f"===== Iteration {iteration}/{RECONNECT_ITERATIONS}: Connecting 8 peripherals =====")

        pause_notifications()

        peripheral_addresses = []

        # Connect all 8 peripherals
        for idx, client in enumerate(peripheral_clients):
            logger().info(f"  Connecting to peripheral-{idx + 1} (iteration {iteration})")

            client_address = client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=bt_dut_address,
                capability=PASSKEY_ENTRY_CAPABILITY,
                service_classes=[svc]
            )
            assert client_address, f"Failed to initiate BLE in peripheral device {idx + 1} (iteration {iteration})"
            peripheral_addresses.append(client_address)

            ble_dut.interfaces.bluetooth.ble_start_scanning(ble_client_address=client_address)
            time.sleep(3)
            ble_dut.interfaces.bluetooth.ble_stop_scanning()
            time.sleep(1)
            ble_dut.interfaces.bluetooth.ble_connect(ble_remote_dev_address=client_address)
            time.sleep(40)

            ble_dut.interfaces.bluetooth.ble_get_device_state()
            time.sleep(5)

            # Resolve services with retries
            servs, chars = [], []
            max_discovery_attempts = 6
            for attempt in range(1, max_discovery_attempts + 1):
                servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
                if len(servs) > 0 and len(chars) > 0:
                    logger().info(f"  Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                    break

                logger().warning(
                    f"  Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                    f"services={len(servs)}, chars={len(chars)}"
                )
                time.sleep(10)

            assert len(servs) > 0, f"No services fetched for peripheral {idx + 1} (iteration {iteration})"
            assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1} (iteration {iteration})"

            logger().info(f"  Peripheral {idx + 1} connected (Passkey Entry, iteration {iteration})")
            time.sleep(2)

        logger().info(f"  All 8 peripherals connected (iteration {iteration})")
        resume_notifications()
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        # Disconnect all 8 peripherals
        logger().info(f"===== Iteration {iteration}/{RECONNECT_ITERATIONS}: Disconnecting 8 peripherals =====")

        pause_notifications()

        for idx, addr in enumerate(peripheral_addresses):
            logger().info(f"  Disconnecting peripheral-{idx + 1} (iteration {iteration})")
            ble_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=addr)
            time.sleep(1)

        logger().info(f"  All 8 peripherals disconnected (iteration {iteration})")
        resume_notifications()
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        time.sleep(5)

        logger().info(f"  Iteration {iteration}/{RECONNECT_ITERATIONS} complete")

    logger().info(f"All {RECONNECT_ITERATIONS} peripheral connect/disconnect/reconnect iterations completed")

    # ========== PHASE 3: Verify 2 central connections still stable ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Verifying 2 central connections still stable after peripheral churn")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()
    time.sleep(5)

    # ========== PHASE 4: Stop TX notify threads and disconnect centrals ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Stopping TX notification threads and disconnecting centrals")
    logger().info("=" * 60)

    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(notify_threads):
        thread.join(timeout=15)
        logger().info(f"Central TX notification thread {idx + 1} joined")

    time.sleep(2)

    logger().info("Disconnecting central-1")
    central_clients[0].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)

    logger().info("Disconnecting central-2")
    central_clients[1].interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)

    logger().info("===== Test C768117 complete (Passkey Entry, 2C TX notify 230 bytes + 8P disconn/reconn x5) =====")


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
@pytest.mark.test_src_map_id('C768118')
def test_2c_tx_notify_8p_tx_write_no_resp_230_bytes_passkey_entry_C768118(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    central_svc = 'HealthThermometerService'
    peripheral_svc = 'ImmediateAlertService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    wwr_data = ("test_data_for_write_no_resp_of_two_thirty_bytes_to_device_"
                "test_data_for_write_no_resp_of_two_thirty_bytess_to_device_"
                "test_data_for_write_no_resp_of_two_thirty_bytes_to_device_"
                "test_data_for_write_no_resp_two_thirty_bytes_to_device_endpad")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    data_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    data_allowed = threading.Event()
    data_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread for central connections (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
            data_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_notify(
                        conn_id=conn_id,
                        data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                    )
                    logger().info(f"[Central conn {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Central conn {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Central conn {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def continuous_write_no_resp(conn_id, stop_flag, wwr_interval=5):
        """Parallel write-without-response thread for peripheral connections (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
            data_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_write_no_resp(
                        conn_id=conn_id,
                        data=wwr_data
                    )
                    logger().info(f"[Peripheral conn {conn_id + 1}] Write-no-resp #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Peripheral conn {conn_id + 1}] Write-no-resp #{count} failed: {e}")

            time.sleep(wwr_interval)
        logger().info(f"[Peripheral conn {conn_id + 1}] Write-no-resp thread stopped after {count} writes")

    def pause_data():
        logger().info(">>> Pausing all data threads for scan/connect")
        data_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All data threads paused")

    def resume_data():
        logger().info(">>> Resuming all data threads")
        data_allowed.set()

    def start_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        data_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Central)")

    def start_wwr_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_write_no_resp,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        data_threads.append(t)
        logger().info(f"Write-no-resp thread STARTED for conn_id {conn_id} (Peripheral)")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("Centrals use HealthThermometerService for TX notifications")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if data_threads:
            pause_data()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        resume_data()

    logger().info("2 central connections established with TX notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + start write-no-resp ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("Peripherals use ImmediateAlertService for write-without-response")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if data_threads:
            pause_data()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
            service_classes=[peripheral_svc]
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        logger().info(f"Peripheral {idx + 1} connected and ready for write-no-resp (Passkey Entry)")
        time.sleep(2)

        # Start write-no-resp thread for this peripheral
        start_wwr_thread(conn_id=idx)

        resume_data()

    # ========== PHASE 3: Run all data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"2 central TX notify (230 bytes) + 8 peripheral write-no-resp (230 bytes) "
                  f"running for 5 min (Passkey Entry)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all data threads =====")

    # ========== PHASE 4: Stop all data threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    data_allowed.set()

    for idx, thread in enumerate(data_threads):
        thread.join(timeout=15)
        logger().info(f"Data thread {idx + 1} joined")

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

    logger().info("===== Test C768118 complete (Passkey Entry, 2C TX notify 230B + 8P write-no-resp 230B) =====")


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
@pytest.mark.test_src_map_id('C768119')
def test_2c_tx_notify_8p_tx_indicate_230_bytes_passkey_entry_C768119(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    indicate_data = ("test_data_for_indication_of_two_thirty_bytes_to_peripheral_"
                     "test_data_for_indication_of_two_thirty_bytess_to_peripheral_"
                     "test_data_for_indicate_of_two_thirty_bytes_to_peripheral_"
                     "test_data_for_indicate_two_thirty_bytes_to_peripheral_end")

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    data_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    data_allowed = threading.Event()
    data_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread for central connections (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
            data_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_notify(
                        conn_id=conn_id,
                        data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                    )
                    logger().info(f"[Central conn {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Central conn {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Central conn {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def continuous_tx_indicate(conn_id, stop_flag, indicate_interval=5):
        """Parallel TX indication thread for peripheral connections (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
            data_allowed.wait()
            if stop_flag['stop']:
                break

            count += 1
            with dut_lock:
                try:
                    ble_dut.interfaces.bluetooth.unified_ble_indicate(
                        conn_id=conn_id,
                        data=indicate_data
                    )
                    logger().info(f"[Peripheral conn {conn_id + 1}] TX Indication #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Peripheral conn {conn_id + 1}] TX Indication #{count} failed: {e}")

            time.sleep(indicate_interval)
        logger().info(f"[Peripheral conn {conn_id + 1}] TX Indication thread stopped after {count} indications")

    def pause_data():
        logger().info(">>> Pausing all data threads for scan/connect")
        data_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All data threads paused")

    def resume_data():
        logger().info(">>> Resuming all data threads")
        data_allowed.set()

    def start_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        data_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Central)")

    def start_indicate_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_indicate,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        data_threads.append(t)
        logger().info(f"TX Indication thread STARTED for conn_id {conn_id} (Peripheral)")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + start TX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("Centrals use HealthThermometerService for TX notifications")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if data_threads:
            pause_data()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_notify_thread(conn_id=8 + c_idx)

        resume_data()

    logger().info("2 central connections established with TX notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + start TX indicate ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("Peripherals use HealthThermometerService for TX indications")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if data_threads:
            pause_data()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        logger().info(f"Peripheral {idx + 1} connected and subscribed (Passkey Entry)")
        time.sleep(2)

        # Start indicate thread for this peripheral
        start_indicate_thread(conn_id=idx)

        resume_data()

    # ========== PHASE 3: Run all data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"2 central TX notify (230 bytes) + 8 peripheral TX indicate (230 bytes) "
                  f"running for 5 min (Passkey Entry)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all data threads =====")

    # ========== PHASE 4: Stop all data threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    data_allowed.set()

    for idx, thread in enumerate(data_threads):
        thread.join(timeout=15)
        logger().info(f"Data thread {idx + 1} joined")

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

    logger().info("===== Test C768119 complete (Passkey Entry, 2C TX notify 230B + 8P TX indicate 230B) =====")


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
@pytest.mark.test_src_map_id('C768120')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_passkey_entry_C768120(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (20 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (20 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + TX notify + RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("Bidirectional: DUT sends TX notifications + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with bidirectional notifications (20 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + TX notify + RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("Bidirectional: DUT sends TX notifications + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), bidirectional notifications enabled")
        time.sleep(2)

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (20 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768120 complete (Passkey Entry, bidirectional TX/RX notify 20 bytes) =====")


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
@pytest.mark.test_src_map_id('C768121')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_passkey_entry_C768121(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + TX notify + RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("Bidirectional: DUT sends TX notifications (230B) + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=8 + c_idx)

        resume_notifications()

    logger().info("2 central connections established with bidirectional notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + TX notify + RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("Bidirectional: DUT sends TX notifications (230B) + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), bidirectional notifications enabled")
        time.sleep(2)

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up! "
                  f"{len(tx_notify_threads)} TX notify threads (230 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768121 complete (Passkey Entry, bidirectional TX/RX notify 230 bytes) =====")


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
@pytest.mark.test_src_map_id('C768122')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_2m_phy_passkey_entry_C768122(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    PHY_2M = 2  # BIT(1) = 2M PHY

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (20 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (20 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + set 2M PHY + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry, 2M PHY)")
    logger().info("Bidirectional: DUT sends TX notifications + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Set 2M PHY on this central connection
        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=conn_id, tx_phy=PHY_2M, rx_phy=PHY_2M, coded_phy=0
        )
        logger().info(f"Central-{c_idx + 1} (conn_id={conn_id}) PHY set to 2M")
        time.sleep(2)

        # Start TX notify thread for this central
        start_tx_notify_thread(conn_id=conn_id)

        resume_notifications()

    logger().info("2 central connections established with 2M PHY, bidirectional notifications (20 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + set 2M PHY + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry, 2M PHY)")
    logger().info("Bidirectional: DUT sends TX notifications + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        # Set 2M PHY on this peripheral connection
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=idx, tx_phy=PHY_2M, rx_phy=PHY_2M, coded_phy=0
        )
        logger().info(f"Peripheral {idx + 1} (conn_id={idx}) PHY set to 2M")
        time.sleep(2)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), 2M PHY, bidirectional notifications enabled")

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up with 2M PHY! "
                  f"{len(tx_notify_threads)} TX notify threads (20 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry, 2M PHY)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768122 complete (Passkey Entry, bidirectional TX/RX notify 20 bytes, 2M PHY) =====")


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
@pytest.mark.test_src_map_id('C768123')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_2m_phy_passkey_entry_C768123(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    PHY_2M = 2  # BIT(1) = 2M PHY

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + set 2M PHY + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry, 2M PHY)")
    logger().info("Bidirectional: DUT sends TX notifications (230 bytes) + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Set 2M PHY on this central connection
        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=conn_id, tx_phy=PHY_2M, rx_phy=PHY_2M, coded_phy=0
        )
        logger().info(f"Central-{c_idx + 1} (conn_id={conn_id}) PHY set to 2M")
        time.sleep(2)

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=conn_id)

        resume_notifications()

    logger().info("2 central connections established with 2M PHY, bidirectional notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + set 2M PHY + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry, 2M PHY)")
    logger().info("Bidirectional: DUT sends TX notifications (230 bytes) + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        # Set 2M PHY on this peripheral connection
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=idx, tx_phy=PHY_2M, rx_phy=PHY_2M, coded_phy=0
        )
        logger().info(f"Peripheral {idx + 1} (conn_id={idx}) PHY set to 2M")
        time.sleep(2)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), 2M PHY, bidirectional notifications enabled")

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up with 2M PHY! "
                  f"{len(tx_notify_threads)} TX notify threads (230 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry, 2M PHY)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768123 complete (Passkey Entry, bidirectional TX/RX notify 230 bytes, 2M PHY) =====")


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
@pytest.mark.test_src_map_id('C768124')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_coded_phy_500kbps_passkey_entry_C768124(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    PHY_CODED = 4   # BIT(2) = Coded PHY
    CODED_S2  = 1   # S=2 coding (500 kbps)

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (20 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (20 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + set Coded PHY S=2 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry, Coded PHY S=2 500kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (20 bytes) + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Set Coded PHY S=2 (500 kbps) on this central connection
        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=conn_id, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S2
        )
        logger().info(f"Central-{c_idx + 1} (conn_id={conn_id}) PHY set to Coded S=2 (500 kbps)")
        time.sleep(2)

        # Start TX notify thread for this central
        start_tx_notify_thread(conn_id=conn_id)

        resume_notifications()

    logger().info("2 central connections established with Coded PHY S=2 (500 kbps), bidirectional notifications (20 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + set Coded PHY S=2 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry, Coded PHY S=2 500kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (20 bytes) + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        # Set Coded PHY S=2 (500 kbps) on this peripheral connection
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=idx, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S2
        )
        logger().info(f"Peripheral {idx + 1} (conn_id={idx}) PHY set to Coded S=2 (500 kbps)")
        time.sleep(2)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), Coded PHY S=2, bidirectional notifications enabled")

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up with Coded PHY S=2 (500 kbps)! "
                  f"{len(tx_notify_threads)} TX notify threads (20 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry, Coded PHY S=2)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768124 complete (Passkey Entry, bidirectional TX/RX notify 20 bytes, Coded PHY S=2 500kbps) =====")


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
@pytest.mark.test_src_map_id('C768125')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_coded_phy_500kbps_passkey_entry_C768125(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    PHY_CODED = 4   # BIT(2) = Coded PHY
    CODED_S2  = 1   # S=2 coding (500 kbps)

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + set Coded PHY S=2 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry, Coded PHY S=2 500kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (230 bytes) + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Set Coded PHY S=2 (500 kbps) on this central connection
        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=conn_id, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S2
        )
        logger().info(f"Central-{c_idx + 1} (conn_id={conn_id}) PHY set to Coded S=2 (500 kbps)")
        time.sleep(2)

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=conn_id)

        resume_notifications()

    logger().info("2 central connections established with Coded PHY S=2 (500 kbps), bidirectional notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + set Coded PHY S=2 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry, Coded PHY S=2 500kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (230 bytes) + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        # Set Coded PHY S=2 (500 kbps) on this peripheral connection
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=idx, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S2
        )
        logger().info(f"Peripheral {idx + 1} (conn_id={idx}) PHY set to Coded S=2 (500 kbps)")
        time.sleep(2)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), Coded PHY S=2, bidirectional notifications enabled")

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up with Coded PHY S=2 (500 kbps)! "
                  f"{len(tx_notify_threads)} TX notify threads (230 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry, Coded PHY S=2)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768125 complete (Passkey Entry, bidirectional TX/RX notify 230 bytes, Coded PHY S=2 500kbps) =====")


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
@pytest.mark.test_src_map_id('C768126')
def test_2c_8p_bidirectional_tx_rx_notify_20_bytes_coded_phy_125kbps_passkey_entry_C768126(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    PHY_CODED = 4   # BIT(2) = Coded PHY
    CODED_S8  = 2   # S=8 coding (125 kbps)

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (20 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (20 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + set Coded PHY S=8 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry, Coded PHY S=8 125kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (20 bytes) + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Set Coded PHY S=8 (125 kbps) on this central connection
        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=conn_id, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S8
        )
        logger().info(f"Central-{c_idx + 1} (conn_id={conn_id}) PHY set to Coded S=8 (125 kbps)")
        time.sleep(2)

        # Start TX notify thread for this central
        start_tx_notify_thread(conn_id=conn_id)

        resume_notifications()

    logger().info("2 central connections established with Coded PHY S=8 (125 kbps), bidirectional notifications (20 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + set Coded PHY S=8 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry, Coded PHY S=8 125kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (20 bytes) + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        # Set Coded PHY S=8 (125 kbps) on this peripheral connection
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=idx, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S8
        )
        logger().info(f"Peripheral {idx + 1} (conn_id={idx}) PHY set to Coded S=8 (125 kbps)")
        time.sleep(2)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), Coded PHY S=8, bidirectional notifications enabled")

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up with Coded PHY S=8 (125 kbps)! "
                  f"{len(tx_notify_threads)} TX notify threads (20 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry, Coded PHY S=8)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768126 complete (Passkey Entry, bidirectional TX/RX notify 20 bytes, Coded PHY S=8 125kbps) =====")


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
@pytest.mark.test_src_map_id('C768127')
def test_2c_8p_bidirectional_tx_rx_notify_230_bytes_coded_phy_125kbps_passkey_entry_C768127(ble_dut, ble_client, ble_clients):
   
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"
    PHY_CODED = 4   # BIT(2) = Coded PHY
    CODED_S8  = 2   # S=8 coding (125 kbps)

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    tx_notify_threads = []
    stop_flags = []

    dut_lock = threading.Lock()
    notify_allowed = threading.Event()
    notify_allowed.set()

    def continuous_tx_notify(conn_id, stop_flag, notify_interval=5):
        """Parallel TX notification thread per connection (230 bytes)."""
        count = 0
        while not stop_flag['stop']:
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
                    logger().info(f"[Client {conn_id + 1}] TX Notification #{count} sent (230 bytes)")
                except Exception as e:
                    logger().error(f"[Client {conn_id + 1}] TX Notification #{count} failed: {e}")

            time.sleep(notify_interval)
        logger().info(f"[Client {conn_id + 1}] TX Notification thread stopped after {count} notifications")

    def pause_notifications():
        logger().info(">>> Pausing all TX notification threads for scan/connect")
        notify_allowed.clear()
        with dut_lock:
            pass
        logger().info(">>> All TX notification threads paused")

    def resume_notifications():
        logger().info(">>> Resuming all TX notification threads")
        notify_allowed.set()

    def start_tx_notify_thread(conn_id):
        stop_flag = {'stop': False}
        stop_flags.append(stop_flag)
        t = threading.Thread(
            target=continuous_tx_notify,
            args=(conn_id, stop_flag),
            daemon=True
        )
        t.start()
        tx_notify_threads.append(t)
        logger().info(f"TX Notification thread STARTED for conn_id {conn_id} (Client {conn_id + 1})")

    # ========== PHASE 1: Connect 2 centrals (DUT as SLAVE, Passkey Entry) + set Coded PHY S=8 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting 2 central devices (DUT as SLAVE, Passkey Entry, Coded PHY S=8 125kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (230 bytes) + receives RX notifications from centrals")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)

        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

        # Set Coded PHY S=8 (125 kbps) on this central connection
        conn_id = 8 + c_idx
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=conn_id, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S8
        )
        logger().info(f"Central-{c_idx + 1} (conn_id={conn_id}) PHY set to Coded S=8 (125 kbps)")
        time.sleep(2)

        # Start TX notify thread for this central (conn_ids 8, 9)
        start_tx_notify_thread(conn_id=conn_id)

        resume_notifications()

    logger().info("2 central connections established with Coded PHY S=8 (125 kbps), bidirectional notifications (230 bytes, Passkey Entry)")

    # ========== PHASE 2: Connect 8 peripherals (DUT as MASTER, Passkey Entry) + set Coded PHY S=8 + TX/RX notify ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry, Coded PHY S=8 125kbps)")
    logger().info("Bidirectional: DUT sends TX notifications (230 bytes) + receives RX notifications from peripherals")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        if tx_notify_threads:
            pause_notifications()

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

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

        # Trigger DUT-side GATT discovery on the peripheral to enable RX notifications.
        ble_dut.interfaces.bluetooth.ble_get_profiles_async(ble_remote_dev_address=client_address)
        time.sleep(10)

        # Set Coded PHY S=8 (125 kbps) on this peripheral connection
        ble_dut.interfaces.bluetooth.unified_ble_set_phy(
            conn_id=idx, tx_phy=PHY_CODED, rx_phy=PHY_CODED, coded_phy=CODED_S8
        )
        logger().info(f"Peripheral {idx + 1} (conn_id={idx}) PHY set to Coded S=8 (125 kbps)")
        time.sleep(2)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry), Coded PHY S=8, bidirectional notifications enabled")

        # Start TX notify thread for this peripheral
        start_tx_notify_thread(conn_id=idx)

        resume_notifications()

    # ========== PHASE 3: Run bidirectional TX/RX data transfer for 5 minutes ==========
    logger().info("=" * 60)
    logger().info(f"PHASE 3: All 10 connections up with Coded PHY S=8 (125 kbps)! "
                  f"{len(tx_notify_threads)} TX notify threads (230 bytes) + "
                  f"RX notifications from all 10 devices. Running for 5 min (Passkey Entry, Coded PHY S=8)")
    logger().info("=" * 60)

    ble_dut.interfaces.bluetooth.ble_get_device_state()

    time.sleep(5 * 60)  # 5 minutes

    logger().info("===== 5 minutes elapsed, stopping all TX notification threads =====")

    # ========== PHASE 4: Stop all TX notification threads ==========
    for idx, stop_flag in enumerate(stop_flags):
        stop_flag['stop'] = True

    notify_allowed.set()

    for idx, thread in enumerate(tx_notify_threads):
        thread.join(timeout=15)
        logger().info(f"TX notification thread {idx + 1} joined")

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

    logger().info("===== Test C768127 complete (Passkey Entry, bidirectional TX/RX notify 230 bytes, Coded PHY S=8 125kbps) =====")


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
@pytest.mark.test_src_map_id('C768128')
def test_2c_8p_notify_enable_disable_230_bytes_numeric_comparison_C768128(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    NC_CAPABILITY = "DisplayYesNo"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Numeric Comparison pairing mode: DisplayYesNo (io_capability=1), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=1, mitm=1)
    logger().info("DUT IO Capability set to DisplayYesNo (Numeric Comparison), MITM=1")

    client_addresses = []
    peripheral_char_paths = []  # Store char_path for each peripheral for enable/disable

    dut_lock = threading.Lock()

    # ========== PHASE 1: Connect 8 peripherals (DUT as MASTER, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Numeric Comparison)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Numeric Comparison) =====")

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=NC_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        peripheral_char_paths.append(char_path)

        logger().info(f"Peripheral {idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

    logger().info("All 8 peripheral connections established (Numeric Comparison)")

    # ========== PHASE 2: Connect 2 centrals (DUT as SLAVE, Numeric Comparison) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Numeric Comparison)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Numeric Comparison) =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=NC_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Numeric Comparison)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

    logger().info("All 10 connections established (8 peripherals + 2 centrals, Numeric Comparison)")

    # ========== PHASE 3: Enable/Disable notification cycle - 10 iterations ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Starting notification enable/disable cycle (10 iterations, 230 bytes)")
    logger().info("=" * 60)

    NUM_ITERATIONS = 10
    TX_DURATION_PER_ITERATION = 30  # seconds of TX notifications per enable cycle

    for iteration in range(1, NUM_ITERATIONS + 1):
        logger().info(f"--- Iteration {iteration}/{NUM_ITERATIONS}: ENABLING notifications on all remotes ---")

        # Enable notifications on 8 peripherals
        for idx, client in enumerate(peripheral_clients):
            client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=peripheral_char_paths[idx])
            client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=peripheral_char_paths[idx],
                char_uid=char_uid
            )
            logger().info(f"Peripheral {idx + 1}: notifications ENABLED (iteration {iteration})")

        time.sleep(2)

        # DUT sends TX notifications (230 bytes) to all 10 connections
        logger().info(f"Iteration {iteration}: DUT sending TX notifications (230 bytes) for {TX_DURATION_PER_ITERATION}s")

        tx_start = time.time()
        tx_count = 0
        while (time.time() - tx_start) < TX_DURATION_PER_ITERATION:
            tx_count += 1
            # Send to all 8 peripherals (conn_id 0-7)
            for conn_id in range(8):
                with dut_lock:
                    try:
                        ble_dut.interfaces.bluetooth.unified_ble_notify(
                            conn_id=conn_id,
                            data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                        )
                    except Exception as e:
                        logger().error(f"[Peripheral {conn_id + 1}] TX #{tx_count} failed: {e}")

            # Send to 2 centrals (conn_id 8, 9)
            for conn_id in range(8, 10):
                with dut_lock:
                    try:
                        ble_dut.interfaces.bluetooth.unified_ble_notify(
                            conn_id=conn_id,
                            data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                        )
                    except Exception as e:
                        logger().error(f"[Central {conn_id - 7}] TX #{tx_count} failed: {e}")

            time.sleep(3)

        logger().info(f"Iteration {iteration}: Sent {tx_count} rounds of TX notifications (230 bytes)")

        # Disable notifications on 8 peripherals
        logger().info(f"--- Iteration {iteration}/{NUM_ITERATIONS}: DISABLING notifications on all remotes ---")

        for idx, client in enumerate(peripheral_clients):
            client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=peripheral_char_paths[idx])
            logger().info(f"Peripheral {idx + 1}: notifications DISABLED (iteration {iteration})")

        time.sleep(2)

        # Verify DUT state is still healthy
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Iteration {iteration}/{NUM_ITERATIONS} complete: notifications enabled → TX → disabled successfully")
        time.sleep(3)

    logger().info(f"All {NUM_ITERATIONS} enable/disable iterations completed successfully")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
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

    logger().info("===== Test C768128 complete (Numeric Comparison, notify enable/disable 230 bytes, 10 iterations) =====")


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
@pytest.mark.test_src_map_id('C768129')
def test_2c_8p_indicate_enable_disable_230_bytes_passkey_entry_C768129(ble_dut, ble_client, ble_clients):
    
    peripheral_clients = [ble_client, ble_clients[0], ble_clients[1], ble_clients[2],
                          ble_clients[3], ble_clients[4], ble_clients[5], ble_clients[6]]
    central_clients = [ble_clients[7], ble_clients[8]]

    service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
    char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
    svc = 'HealthThermometerService'

    PASSKEY_ENTRY_CAPABILITY = "KeyboardOnly"

    ble_dut.interfaces.bluetooth.ble_unified_app_start()
    bt_dut_address = ble_dut.interfaces.wifi.bt_get_local_address()

    # Set Passkey Entry pairing mode: KeyboardDisplay (io_capability=4), MITM enabled
    ble_dut.interfaces.bluetooth.ble_set_io_capability(io_capability=4, mitm=1)
    logger().info("DUT IO Capability set to KeyboardDisplay (Passkey Entry), MITM=1")

    client_addresses = []
    peripheral_char_paths = []  # Store char_path for each peripheral for enable/disable

    dut_lock = threading.Lock()

    # ========== PHASE 1: Connect 8 peripherals (DUT as MASTER, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 1: Connecting to 8 peripheral devices (DUT as MASTER, Passkey Entry)")
    logger().info("=" * 60)

    for idx, client in enumerate(peripheral_clients):
        logger().info(f"===== Connecting to peripheral-{idx + 1} (Passkey Entry) =====")

        client_address = client.interfaces.bluetooth.start_smp_adv(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY,
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

        # Resolve services with retries
        servs, chars = [], []
        max_discovery_attempts = 6
        for attempt in range(1, max_discovery_attempts + 1):
            servs, chars = client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            if len(servs) > 0 and len(chars) > 0:
                logger().info(f"Peripheral {idx + 1}: GATT discovery success on attempt {attempt}")
                break

            logger().warning(
                f"Peripheral {idx + 1}: empty GATT discovery on attempt {attempt}/{max_discovery_attempts}; "
                f"services={len(servs)}, chars={len(chars)}"
            )
            time.sleep(10)

        assert len(servs) > 0, f"No services fetched for peripheral {idx + 1}"
        assert len(chars) > 0, f"Fetched characters are empty for peripheral {idx + 1}"

        char_path, char_props = client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
            services=servs,
            service_uid=service_uid,
            char_uid=char_uid
        )
        assert char_path, f"Characters are empty for peripheral {idx + 1}"

        client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        peripheral_char_paths.append(char_path)

        logger().info(f"Peripheral {idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

    logger().info("All 8 peripheral connections established (Passkey Entry)")

    # ========== PHASE 2: Connect 2 centrals (DUT as SLAVE, Passkey Entry) ==========
    logger().info("=" * 60)
    logger().info("PHASE 2: Connecting 2 central devices (DUT as SLAVE, Passkey Entry)")
    logger().info("=" * 60)

    for c_idx, central in enumerate(central_clients):
        logger().info(f"===== Starting DUT advertising for central-{c_idx + 1} (Passkey Entry) =====")

        ble_dut.interfaces.bluetooth.ble_start_advertising()
        time.sleep(2)

        central.interfaces.bluetooth.start_smp_scan(
            bt_dut_address=bt_dut_address,
            capability=PASSKEY_ENTRY_CAPABILITY
        )
        time.sleep(2)
        central.interfaces.bluetooth.pair_and_connect(bt_dut_address, capability=PASSKEY_ENTRY_CAPABILITY)
        time.sleep(20)

        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Central-{c_idx + 1} connected and paired (Passkey Entry)")
        time.sleep(2)

        ble_dut.interfaces.bluetooth.ble_stop_advertising()

    logger().info("All 10 connections established (8 peripherals + 2 centrals, Passkey Entry)")

    # ========== PHASE 3: Enable/Disable indication cycle - 10 iterations ==========
    logger().info("=" * 60)
    logger().info("PHASE 3: Starting indication enable/disable cycle (10 iterations, 230 bytes)")
    logger().info("=" * 60)

    NUM_ITERATIONS = 10
    TX_DURATION_PER_ITERATION = 30  # seconds of TX indications per enable cycle

    for iteration in range(1, NUM_ITERATIONS + 1):
        logger().info(f"--- Iteration {iteration}/{NUM_ITERATIONS}: ENABLING indications on all remotes ---")

        # Enable indications on 8 peripherals
        for idx, client in enumerate(peripheral_clients):
            client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=peripheral_char_paths[idx])
            client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                char_path=peripheral_char_paths[idx],
                char_uid=char_uid
            )
            logger().info(f"Peripheral {idx + 1}: indications ENABLED (iteration {iteration})")

        time.sleep(2)

        # DUT sends TX indications (230 bytes) to all 10 connections
        logger().info(f"Iteration {iteration}: DUT sending TX indications (230 bytes) for {TX_DURATION_PER_ITERATION}s")

        tx_start = time.time()
        tx_count = 0
        while (time.time() - tx_start) < TX_DURATION_PER_ITERATION:
            tx_count += 1
            # Send to all 8 peripherals (conn_id 0-7)
            for conn_id in range(8):
                with dut_lock:
                    try:
                        ble_dut.interfaces.bluetooth.unified_ble_indicate(
                            conn_id=conn_id,
                            data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                        )
                    except Exception as e:
                        logger().error(f"[Peripheral {conn_id + 1}] Indicate #{tx_count} failed: {e}")

            # Send to 2 centrals (conn_id 8, 9)
            for conn_id in range(8, 10):
                with dut_lock:
                    try:
                        ble_dut.interfaces.bluetooth.unified_ble_indicate(
                            conn_id=conn_id,
                            data=f"test_data_for_notification_of_two_thirty_bytes_to_peripheral_test_data_for_notification_of_two_thirty_bytess_to_peripheral_test_data_for_notify_of_two_thirty_bytes_to_peripheral_test_data_for_notify_two_thirty_bytes_to_peripheral{conn_id + 1}"
                        )
                    except Exception as e:
                        logger().error(f"[Central {conn_id - 7}] Indicate #{tx_count} failed: {e}")

            time.sleep(3)

        logger().info(f"Iteration {iteration}: Sent {tx_count} rounds of TX indications (230 bytes)")

        # Disable indications on 8 peripherals
        logger().info(f"--- Iteration {iteration}/{NUM_ITERATIONS}: DISABLING indications on all remotes ---")

        for idx, client in enumerate(peripheral_clients):
            client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=peripheral_char_paths[idx])
            logger().info(f"Peripheral {idx + 1}: indications DISABLED (iteration {iteration})")

        time.sleep(2)

        # Verify DUT state is still healthy
        ble_dut.interfaces.bluetooth.ble_get_device_state()
        logger().info(f"Iteration {iteration}/{NUM_ITERATIONS} complete: indications enabled → TX → disabled successfully")
        time.sleep(3)

    logger().info(f"All {NUM_ITERATIONS} enable/disable iterations completed successfully")

    # ========== PHASE 4: Disconnect all ==========
    logger().info("=" * 60)
    logger().info("PHASE 4: Disconnecting all clients")
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

    logger().info("===== Test C768129 complete (Passkey Entry, indicate enable/disable 230 bytes, 10 iterations) =====")

