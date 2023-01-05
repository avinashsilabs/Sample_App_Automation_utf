import time
import pytest
import random, string
from retry import retry
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect.devices.rs911x import RS9116AsyncEventType
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ConfigFeatureBitMap
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs


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


@retry(Exception, delay=15, tries=3)
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
            enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifi_ps, "Failed to enable WIFI power save"
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
            enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            assert enable_wifi_ps, "Failed to enable WIFI power save"
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


@retry(Exception, delay=15, tries=3)
def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True):
    ble_client_address = None
    ble_dut_address = ble_dut_address
    if mode == "ble_master":
        ble_client.interfaces.bluetooth.close()
        if start_needed:
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            time.sleep(3)
            assert ble_dut_address, f"Unable to get ble_dut_address"
            logger().info(f"Started BLE in DUT")
        logger().info(f"Start ble client")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to get ble_client_address"
        time.sleep(5)
        try:
            logger().info(f"****** ADDING WHITELIST BEFORE SCANNING")
            wifi_dut.interfaces.wifi.ble_add_white_list(ble_client_address)
            logger().info(f"Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, ble_scan_filter_type=1,
                                                        timeout=120)
            # wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            timeout = 200
            logger().info(f"DUT initiating BLE connection with ble_client device")
            wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)
            logger().info("******** BLE master connection successful ********")
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            ble_client.interfaces.bluetooth.stop_advertising()
            wifi_dut.interfaces.wifi.ble_stop_scanning()
            raise e

    if mode == "ble_slave":
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        if start_needed:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to get ble_dut_address"
        try:
            wifi_dut.interfaces.wifi.ble_start_advertising()
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(
                bt_dut_address=ble_dut_address,
            )
            assert ble_client_address, "Unable to get ble_client_address from remote device"
            logger().info("keeping the time sleep to complete smp scan")
            time.sleep(4)
            # self.ble_client.interfaces.bluetooth.stop_scanning()
            logger().info(f"See that we found our device")
            dut_ble_address = wifi_dut.interfaces.wifi.ble_address
            logger().info(f"dut_ble_address: {dut_ble_address}")
            device_found = False
            sw = Stopwatch()
            while sw.elapsed_sec < 30:
                found_devices = ble_client.interfaces.bluetooth.get_devices()
                if (
                        wifi_dut.interfaces.wifi.ble_address in found_devices
                        and found_devices[dut_ble_address]
                        == wifi_dut.interfaces.wifi.ble_advertising_data
                ):
                    device_found = True
                    logger().info(f"ble_scan_list:\n{found_devices}")
                    break
            ble_client.interfaces.bluetooth.stop_scanning()
            assert device_found
            logger().info(f"See that we found our device:'{ble_dut_address}'")
            logger().info("Initiating BLE connection from ble_client device")
            conn_params = {"min_conn_interval": 40,
                           "max_conn_interval": 40,
                           "conn_latency": 0,
                           "supervision_timeout": 200}

            ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
            logger().info(f"******** BLE slave connection successful ********")
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            ble_client.interfaces.bluetooth.stop_scanning()
            raise e
    return ble_client_address, ble_dut_address


def bt_disconnect(wifi_dut, bt_client_address, bt_socket):
    # Close BT connection
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    bt_socket.close()
    time.sleep(3)
    logger().info("Successfully disconnected from BT SLAVE Device")


def ble_disconnect(wifi_dut, ble_client_address):
    # Ble disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=120)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")


def check_connection_status(wifi_dut, ble_dut_address=None, ble_clients=None):
    logger().info("\n********************** Checking connection status of BT from DUT ***********************")
    rsi_bt_on_spp_disconnect = False
    rsi_bt_on_disconn_event = False
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            logger().info(f"event type:'{event.event_type}'")
            if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_SPP_DISCONN:
                rsi_bt_on_spp_disconnect = True
            if event.event_type == RS9116AsyncEventType.RSI_APP_EVENT_DISCONNECTED:
                rsi_bt_on_disconn_event = b"4E13" in event.event_data
        if rsi_bt_on_spp_disconnect or rsi_bt_on_disconn_event:
            logger().info("DUT is disconnected from BT")
            assert False, "DUT is disconnected from BT"
        logger().info("\n************************** DUT is not disconnected from BT *****************************")

    logger().info("\n********************** Checking connection status of BLE from DUT **********************")
    for retry_count in range(5):
        try:
            state = wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT is not connected to remote BLE device"
            break
        except Exception as err:
            logger().info(f"Exception occurred while getting ble device state:\nException is: {err}")
            logger().info(f"retry_count: {retry_count + 1}")
            time.sleep(15)
    logger().info("\n******************* DUT is not disconnected from remote BLE device *********************")

    if ble_clients:
        for ble_client in ble_clients:
            logger().info(
                f"\n***************** Checking connection status of BLE from Raspi Device {ble_client.name} ******************")

            status = ble_client.interfaces.bluetooth.get_connection_status(ble_dut_address)
            logger().info(f"Connection status in remote device is:{status}")
            assert status, f"Remote device is not connected to DUT '{ble_dut_address}'"
            logger().info(f"\n************* Remote BLE device still connected to DUT '{ble_dut_address}' *************")


def connect_disconnect_ble(wifi_dut, ble_client, ble_client_address, iter_count):
    for i in range(1, iter_count + 1):
        logger().info(f"Initiating BLE disconnection...iteration: '{i}'")
        ble_disconnect(wifi_dut, ble_client_address)
        logger().info(f"Disconnect completed...iteration: '{i}'")
        time.sleep(3)
        logger().info(f"Re-Initiating BLE connection...iteration: '{i}'")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to get ble_dut_address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(3)
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info(f"DUT successfully connected to {ble_client} Device...iteration: '{i}'")
        time.sleep(3)


def connect_disconnect_bt(wifi_dut, bt_client, bt_address, bt_dut_address, bt_socket, iter_count=5,
                          data_transfer=False):
    send_text = text_generator()
    recv_text = text_generator()
    logger().info("Initiating BT disconnection on DUT")
    for i in range(1, iter_count + 1):
        logger().info(f"\n\nInitiating BT disconnection from raspi device...iteration: '{i}'")
        bt_client.interfaces.bluetooth.bt_device.disconnect_device(bt_dut_address)
        bt_socket.close()
        logger().info("Waiting for some time to complete bt disconnection")
        time.sleep(10)
        logger().info(f"BT disconnection success...iteration: '{i}'")

        logger().info(f"\nRe-Initiating BT connection from raspi device...iteration: '{i}'")
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"Raspi device initiating bt connection with DUT, this can take some time....")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=10)
            assert connected, "Unable to connect to DUT from raspi device"
            time.sleep(10)
        logger().info(
            f"bt_client:' {bt_client.name}' Successfully connected to DUT: '{bt_dut_address}'")
        bt_socket = bt_server_socket
        logger().info(f"BT connection success...iteration: '{i}'")
        # Ping dut
        logger().info("Pinging to DUT from raspi device")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
        logger().info(f"Successfully pinged to DUT from bt_client....iteration: '{i}'")
        time.sleep(5)
        if data_transfer:
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
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_address)
            data = bt_server_socket.recv()
            logger().info(f"Data: '{send_text}' sent from DUT to bt_client.")
            logger().info(f"Data received back from bt_client is......'{data.decode()}'")
            assert data is not None, f"Data not received back from bt_client"
            assert data.decode() == send_text
            logger().info(f"Send data from dut to bt_client is successful")

    logger().info("BT Connect-Disconnect thread completed")


def dut_clean_up(wifi_dut, bt_socket=None):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT ----------------------------")
    try:

        logger().info("BT disconnect from DUT")
        try:
            for bt_client_address in wifi_dut.interfaces.wifi.bt_devices_address:
                wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
        except:
            pass
        if bt_socket is not None:
            logger().info("Closing opened BT sockets in bt_client")
            bt_socket.close()
            time.sleep(5)
        logger().info("BLE disconnect from DUT")
        try:
            for ble_client_address in wifi_dut.interfaces.wifi.ble_devices_address:
                wifi_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        except:
            pass
    except Exception as err:
        logger().info(
            f"******* Exception occurred while cleaning up the DUT\nException is:{err}\nRecovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed ----------------------------")


# test agent used is coex_custom_test_agent.hex
pytestmark = [pytest.mark.bt_client("raspi_bt_client"), pytest.mark.ble_client("secondary_raspi_ble_client"),
              pytest.mark.firmware_app("test_coex_custom")]


# Verify BT_BLE functionality when BT and BLE in SLAVE mode
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_with_bt_ble_as_slave_C19993(firmware_loader, wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19993.log_{int(time.time())}"):
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
            check_connection_status(wifi_dut, ble_dut_address)

    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Verify BT_BLE functionality when BT and BLE in MASTER mode
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_with_bt_ble_as_master_C19994(firmware_loader, wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19994.log_{int(time.time())}"):
            bt_mode = "bt_master"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info("Checking connection status of BT, BLE")
            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Verify BT_BLE functionality when BT in SLAVE mode, BLE in DUAL_ROLE
# Minimum three raspberry pi required for the test connection
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_with_ble_as_dual_role_C19995(firmware_loader, wifi_dut, bt_client, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_socket = None

    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
    for ble_client in ble_clients:
        if str(ble_client.name).split('_')[0] == str(bt_client.name).split('_')[0]:
            message = "Same raspi device is used in bt_client and ble_clients, this is not supported. Please use 3 " \
                      "different raspi's for this testcase "
            logger().error(message)
            pytest.xfail(message)
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19995.log_{int(time.time())}"):
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(f"bt_dut_address '{bt_dut_address}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
            logger().info(f"ble_dut_address after ble_slave connection '{ble_dut_address}'")

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address,
                                                            start_needed=False)

            logger().info("Checking connection status of BT, BLE")
            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address, ble_clients)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Verify connection stability of RSI_BT and RSI_BLE with remote devices
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_stability_C19996(firmware_loader, wifi_dut, bt_client, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
    for ble_client in ble_clients:
        if str(ble_client.name).split('_')[0] == str(bt_client.name).split('_')[0]:
            message = "Same raspi device is used in bt_client and ble_clients, this is not supported. Please use 3 " \
                      "different raspi's for this testcase "
            logger().error(message)
            pytest.xfail(message)
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19996.log_{int(time.time())}"):
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
            logger().info(f"ble_dut_address after ble_slave connection '{ble_dut_address}'")

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address)

            logger().info("keeping the setup undisturbed for 60 seconds ")
            time.sleep(60)
            logger().info("Checking connection status of BT, BLE after 60 seconds of undisturbed setup ")
            check_connection_status(wifi_dut, ble_dut_address, ble_clients)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_BT_SPP_Tx_Rx_BLE_connectivity_C19997(firmware_loader, wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19997.log_{int(time.time())}"):
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(f"bt_address: '{bt_address}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_address: '{ble_address}'")

            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address)

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
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Verify the DUAL_MODE functionality if BT_BLE while all the devices are connected and data transfer is in progress
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_with_dual_mode_functionality_C19998(firmware_loader, wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19998.log_{int(time.time())}"):
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

            logger().info("Checking connection status of BT, BLE")
            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address)

            logger().info("Initiating BT disconnection on DUT")
            bt_disconnect(wifi_dut, bt_address, bt_socket)

            logger().info("Initiating BLE disconnection on DUT")
            ble_disconnect(wifi_dut, ble_address)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# BT connect and disconnect while BLE is in connection
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_BT_connect_and_disconnect_BLE_is_in_connection_C19999(firmware_loader, wifi_dut, bt_client, utf_constants, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    iter_count = utf_constants.get("iter_count")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C19999.log_{int(time.time())}"):
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

            logger().info("Checking connection status of BT, BLE,")
            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address)

            logger().info("Pinging to DUT from bt_client before disconnecting and connecting in iteration")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address, count=10)
            logger().info("Successfully pinged to DUT from bt_client")

            logger().info(f"Initiating connect disconnect bt for 5 iterations")
            connect_disconnect_bt(wifi_dut, bt_client, bt_address, bt_dut_address, bt_socket, iter_count=iter_count,
                                  data_transfer=True)

            logger().info("Initiating BLE disconnection on DUT")
            ble_disconnect(wifi_dut, ble_address)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Verify BLE connect and disconnect multiple times while BT are connected with remote devices and data transfer is in progress
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_with_ble_connect_disconnect_C20000(firmware_loader, wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C20000.log_{int(time.time())}"):
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

            logger().info("Checking connection status of BT, BLE")
            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address)

            logger().info("Initiating BLE connection and disconnection for 5 iterations")
            connect_disconnect_ble(wifi_dut, ble_client, ble_address, iter_count=5)

            logger().info("Checking connection status of BT, BLE")
            check_connection_status(wifi_dut, ble_dut_address)

            logger().info("Initiating BT disconnection on DUT")
            bt_disconnect(wifi_dut, bt_address, bt_socket)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Verify Power save 2 functionality of DUT when configured in STA_BT_BLE mode. Check if connectivity and data
# transfer is functional.
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_bt_ble_connection_with_powersave_mode2_C20001(firmware_loader, wifi_dut, bt_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C20001.log_{int(time.time())}"):
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

            time.sleep(3)

            logger().info("Checking connection status of BT, BLE")
            check_connection_status(wifi_dut, ble_dut_address)
    finally:
        dut_clean_up(wifi_dut, bt_socket)


# Multiple BLE Device connection support is required in Test Agent Side
# https://jira.silabs.com/browse/WIFI_BT_UTFHELP-647
# Three raspberry pi required to test this test case
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_dual_role_functionality_of_BLE_BT_in_connection_C20002(firmware_loader, wifi_dut, bt_client, ble_clients):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_socket = None

    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
    for ble_client in ble_clients:
        if str(ble_client.name).split('_')[0] == str(bt_client.name).split('_')[0]:
            message = "Same raspi device is used in bt_client and ble_clients, this is not supported. Please use 3 " \
                      "different raspi's for this testcase "
            logger().error(message)
            pytest.xfail(message)
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_bt_ble_C20002.log_{int(time.time())}"):
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address)

            logger().info("Checking connection status of BT, BLE")
            time.sleep(60)
            check_connection_status(wifi_dut, ble_dut_address, ble_clients)
    finally:
        dut_clean_up(wifi_dut, bt_socket)
