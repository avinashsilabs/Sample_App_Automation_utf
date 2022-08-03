import time
import pytest
import random, string
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ConfigFeatureBitMap
from utf.interfaces.bluetooth import BLEDeviceState


def logger():
    return get_logger(__name__)


"""
    Setup Requirement: DUT(RS9116) , EFR32, 3 Raspberry PI required [ 2 BLE CLIENTS],
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by cg team, pallavi
    Description:BT_BLE Test cases
"""


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def bt_spp_master_slave(wifi_dut, bt_client, mode):
    send_text = text_generator()
    recv_text = text_generator()
    if mode == "bt_slave":
        bt_client.interfaces.bluetooth.close()
        logger().info("Setting DUT as bt_slave....")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None, f"Unable to get bt_dut_address"
        logger().info("Advertising started on BT SLAVE device....DUT")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None, f"Unable to get bt_client_address"
        logger().info("Started BT in MASTER device....bt_client")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=6)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"DUT initiating bt connection with SLAVE device, this can take some time....")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected
        logger().info(f"bt_client:' {bt_client_address}' Successfully connected to DUT: '{bt_dut_address}'")

        # Initiating power save
        logger().info("Initiating power save on DUT")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_bt_ps, "failed to enable bt power save"
            logger().info("DUT is on power save mode")

        # Send data from bt_client to dut
        logger().info("Sending data from bt_client to DUT.")
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
            logger().info(f"Data: '{recv_text}' sent from bt_client to DUT.....'{sent}'")
            assert sent, f"Not sent data from bt_client to DUT"
            data = bt_server_socket.recv()
            logger().info(f"Data received back from DUT is......'{data.decode()}'")
            assert data is not None, f"Data not received back from DUT "
            assert data.decode() == recv_text
            logger().info(f"Send data from bt_client to dut is successful")

        # Send data from dut to bt_client
        logger().info("Sending data from DUT to bt_client.")
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_server_socket.recv()
        logger().info(f"Data: '{send_text}' sent from DUT to bt_client.")
        logger().info(f"Data received back from bt_client is......'{data.decode()}'")
        assert data is not None, f"Data not received back from bt_client"
        assert data.decode() == send_text
        logger().info(f"Send data from dut to bt_client is successful")

        # Ping dut
        logger().info("Pinging to DUT from bt_client")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info("Successfully pinged to DUT from bt_client")
        return bt_client_address, bt_server_socket, bt_dut_address

    if mode == "bt_master":
        # Initiating power save
        bt_client.interfaces.bluetooth.close()
        logger().info("Initiating power save on DUT")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_bt_ps, "failed to enable bt power save"

        logger().info("Setting DUT as bt_master....")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address is not None, f"Unable to get bt_dut_address"
        logger().info("Started BT in MASTER device....DUT")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address is not None, f"Unable to get bt_client_address"
        logger().info("Advertising started on SLAVE device....bt_client")
        time.sleep(3)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                               inquiry_duration_ms=20000, timeout=22, retry_counts=6)
        if not found:
            logger().warning(f"Dut unable to find the bt client device. The test case may fail.")

        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_client_socket.create_client()
            logger().info(f"DUT Initiating bt connection with SLAVE device, this can take some time....")
            wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
            addr = bt_client_socket.accept(timeout=120)
            assert addr == bt_dut_address, f"BT DUT Address not found"
        logger().info(f"DUT: '{bt_dut_address}' Successfully connected to bt_client: '{bt_client_address}'")

        # Send data from bt_client to dut
        time.sleep(20)
        logger().info("Sending data from bt_client to DUT.")
        with wifi_dut.interfaces.wifi.run_bt_task():
            sent = bt_client_socket.send(recv_text)  # Dut is programmed to send back data
            logger().info(f"Data: '{recv_text}' sent from bt_client to DUT.....'{sent}'")
            assert sent
            time.sleep(2)
            data = bt_client_socket.recv()
            logger().info(f"Data received back from DUT is......'{data.decode()}'")
            assert data is not None, f"Data not received back from DUT "
            assert data.decode() == recv_text
            logger().info(f"Send data from bt_client to dut is successful")

        # Send data from dut to bt_client
        logger().info("Sending data from DUT to bt_client.")
        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
        data = bt_client_socket.recv()
        logger().info(f"Data: '{send_text}' sent from DUT to bt_client.")
        logger().info(f"Data received back from bt_client is......'{data.decode()}'")
        assert data is not None, f"Data received back from bt_client"
        assert data.decode() == send_text
        logger().info("Send data from DUT to bt_client is successful.")

        # Ping dut
        logger().info("Pinging to DUT from bt_client")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info("Successfully pinged to DUT from bt_client")

        # returning value for closing the connection
        return bt_client_address, bt_client_socket, bt_dut_address


def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None):
    ble_client_address = None
    if mode == "ble_master":
        ble_client.interfaces.bluetooth.close()
        if ble_dut_address is None:
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            time.sleep(3)
            assert ble_dut_address is not None, f"Unable to get ble_dut_address"
            logger().info(f"Started BLE in DUT")
        logger().info(f"Start ble client")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address is not None, f"Unable to get ble_client_address"
        time.sleep(5)
        logger().info(f"Start scanning and connect to ble client")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=100)
        timeout = 120
        logger().info(f"connect")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)
        logger().info(f"Connect success")

    if mode == "ble_slave":
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        if ble_dut_address is None:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address is not None, f"Unable to get ble_dut_address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(3)
        logger().info(f"Begin Scanning for BLE devices")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address is not None, f"Unable to get ble_client_address"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data)
        logger().info("Connecting ble_client to DUT")
        conn_params = {"min_conn_interval": 40,
                       "max_conn_interval": 40,
                       "conn_latency": 0,
                       "supervision_timeout": 120}

        ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                min_conn_interval=conn_params["min_conn_interval"],
                                                max_conn_interval=conn_params["max_conn_interval"],
                                                conn_latency=conn_params["conn_latency"],
                                                supervision_timeout=conn_params["supervision_timeout"])
        logger().info("Connect ble_client to DUT successful")
    return ble_client_address, ble_dut_address


def bt_disconnect(wifi_dut, bt_client_address, bt_socket):
    # Close BT connection
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    bt_socket.close()
    time.sleep(3)
    logger().info("Successfully disconnected from BT SLAVE Device")


def ble_disconnect(wifi_dut, ble_client_address):
    # Ble disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)
    # ble_client.interfaces.bluetooth.disconnect(ble_address)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")


def check_connection_status(wifi_dut):
    rsi_bt_on_spp_disconnect = False
    rsi_bt_on_disconn_event = False
    events = wifi_dut.interfaces.wifi.get_async_events()
    logger().info(f"printing the events '{events}'")
    if len(events):
        for event in events:
            logger().info(f"printing the event type {event.event_type}")
            if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                rsi_bt_on_spp_disconnect = True
            if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                rsi_bt_on_disconn_event = b"4E13" in event.event_data
        if rsi_bt_on_spp_disconnect or rsi_bt_on_disconn_event:
            logger().info("DUT is disconnected from BT")
            assert False, "DUT is disconnected from BT"
        else:
            logger().info("DUT is not disconnected from BT")

    logger().info("Checking connection status of BLE")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
    logger().info("DUT is not disconnected from BLE")


def connect_disconnect_ble(wifi_dut, ble_client, ble_client_address, iter_count):
    for i in range(1, iter_count + 1):
        logger().info(f"Initiating BLE disconnection...iteration: '{i}'")
        ble_disconnect(wifi_dut, ble_client_address)
        logger().info(f"Disconnect completed...iteration: '{i}'")
        time.sleep(3)
        logger().info(f"Re-Initiating BLE connection...iteration: '{i}'")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address is not None, f"Unable to get ble_dut_address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info(f"DUT successfully connected to {ble_client} Device...iteration: '{i}'")
        time.sleep(3)


def connect_disconnect_bt(wifi_dut, bt_client, bt_address, bt_dut_address, iter_count):
    logger().info("Initiating BT disconnection on DUT")
    for i in range(1, iter_count):
        logger().info(f"bt address for iteration '{i}' is '{bt_address}'")
        logger().info(f"Initiating BT disconnection on DUT...iteration: '{i}'")
        wifi_dut.interfaces.wifi.bt_disconnect(bt_address)
        time.sleep(10)
        logger().info(f"BT disconnection success...iteration: '{i}'")

        logger().info(f"Re-Initiating BT connection on DUT...iteration: '{i}'")
        wifi_dut.interfaces.wifi.bt_connect(bt_address, timeout=20)
        time.sleep(5)
        logger().info(f"BT connection success to '{bt_client}' for iteration: '{i}'")
        logger().info(f"Ping check to check connectivity of BT")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address, count=3)
        #time.sleep(10)
    logger().info("BT Connect-Disconnect completed")


# Verify BT_BLE functionality when BT and BLE in SLAVE mode
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    }
)
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_with_bt_ble_as_slave_C19993(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_address: '{bt_address}'")

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_address}'")
    logger().info(f"ble_dut_address: '{ble_dut_address}'")

    logger().info("Checking connection status of BT, BLE")
    time.sleep(60)
    check_connection_status(wifi_dut)

    logger().info("Initiating BT reset on DUT")
    bt_client.interfaces.bluetooth.bt_adapter.reset()
    wifi_dut.interfaces.wifi.bt_deinit()

# Verify BT_BLE functionality when BT and BLE in MASTER mode
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_with_bt_ble_as_master_C19994(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_master"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status of BT, BLE")
    time.sleep(60)
    check_connection_status(wifi_dut)

    wifi_dut.interfaces.wifi.bt_deinit()


# Verify BT_BLE functionality when BT in SLAVE mode, BLE in DUAL_ROLE
# Minimum three raspberry pi required for the test connection
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_with_ble_as_dual_role_C19995(wifi_dut, bt_client, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_dut_address '{bt_dut_address}'")

    logger().info("Initiating power save on DUT")
    if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        wifi_dut.interfaces.wifi.set_sleep_gpio(True)
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        assert enable_bt_ps, "failed to enable bt power save"

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
    logger().info(f"ble_dut_address after ble_slave connection '{ble_dut_address}'")

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address)

    logger().info("Checking connection status of BT, BLE")
    time.sleep(60)
    check_connection_status(wifi_dut)


# Verify connection stability of RSI_BT and RSI_BLE with remote devices
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_stability_C19996(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status of BT, BLE")
    check_connection_status(wifi_dut)

    # can check in loop
    logger().info("keeping the setup undisturbed for 60 seconds ")
    time.sleep(60)
    logger().info("Checking connection status of BT, BLE after 60 seconds of undisturbed setup ")
    check_connection_status(wifi_dut)


@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_BT_SPP_Tx_Rx_BLE_connectivity_C19997(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_address: '{bt_address}'")

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_address}'")

    time.sleep(60)
    check_connection_status(wifi_dut)

    send_text = text_generator()

    # Send data from dut to bt_client
    logger().info("Sending data from DUT to bt_client SPP RX")
    wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_address)
    data = bt_socket.recv()
    logger().info(f"Data: '{send_text}' sent from DUT to bt_client.")
    logger().info(f"Data received back from bt_client is......'{data.decode()}'")
    assert data is not None, f"Data not received back from bt_client"
    assert data.decode() == send_text
    logger().info(f"Send data from dut to bt_client is successful")

    # Rx data from bt_client to DUT
    logger().info("RX data to DUT from bt_client")
    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
    logger().info("Successfully pinged to DUT from bt_client")


# Verify the DUAL_MODE functionality if BT_BLE while all the devices are connected and data transfer is in progress
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_with_dual_mode_functionality_C19998(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status of BT, BLE")
    time.sleep(60)
    check_connection_status(wifi_dut)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

# BT connect and disconnect while BLE is in connection
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_BT_connect_and_disconnect_BLE_is_in_connection_C19999(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status of BT, BLE,")
    time.sleep(60)
    check_connection_status(wifi_dut)

    logger().info("Pinging to DUT from bt_client")
    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address, count=10)
    logger().info("Successfully pinged to DUT from bt_client")

    logger().info(f"Initiating connect disconnect bt for 5 iterations")
    connect_disconnect_bt(wifi_dut, bt_client, bt_address, bt_dut_address, iter_count=5)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)


# Verify BLE connect and disconnect multiple times while BT are connected with remote devices and data transfer is in progress
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_with_ble_connect_disconnect_C20000(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status of BT, BLE")
    time.sleep(60)
    check_connection_status(wifi_dut)

    logger().info("Initiating BLE connection and disconnection for 5 iterations")
    connect_disconnect_ble(wifi_dut, ble_client, ble_address, iter_count=5)

    logger().info("Checking connection status of BT, BLE")
    check_connection_status(wifi_dut)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify Power save 2 functionality of DUT when configured in STA_BT_BLE mode. Check if connectivity and data transfer is functional.
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_bt_ble_connection_with_powersave_mode2_C20001(wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save2
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
    assert enable_bt_ps, "failed to enable bt power save"
    time.sleep(3)

    logger().info("Checking connection status of BT, BLE")
    check_connection_status(wifi_dut)


# Multiple BLE Device connection support is required in Test Agent Side
# https://jira.silabs.com/browse/WIFI_BT_UTFHELP-647
# Three raspberry pi required to test this test case
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["bt_powersave_disable", "bt_disconnect", "ble_disconnect"])
def test_dual_role_functionality_of_BLE_BT_in_connection_C20002(wifi_dut, bt_client, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    logger().info("Initiating power save on DUT")
    if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        wifi_dut.interfaces.wifi.set_sleep_gpio(True)
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        assert enable_bt_ps, "failed to enable bt power save"

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address)

    logger().info("Checking connection status of BT, BLE")
    time.sleep(60)
    check_connection_status(wifi_dut)
