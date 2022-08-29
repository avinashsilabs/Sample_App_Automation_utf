import re
import time
import pytest
import random, string
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf.interfaces.bluetooth import BTSocketRole
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveProcedureTypes
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_interface import (BTRole, BTProfile, BTEvents, )


ping_count = 30


def logger():
    return get_logger(__name__)

"""
    Setup Requirement: DUT(RS9116) , EFR32, 3 Raspberry PI required ,
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by cg team : Rashmi & team
    Description: STA_BT_BLE Test cases
"""


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def wifi_join(wifi_dut, wifi_access_point):
    time.sleep(5)
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    result = wifi_dut.interfaces.wifi.start_ip()
    assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    enable_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_ps, "failed to enable power save"
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")
    time.sleep(10)
    return device_ip


def bt_spp_master_slave(wifi_dut, bt_client, mode):
    send_text = text_generator()
    recv_text = text_generator()
    if mode == "bt_slave":
        bt_client.interfaces.bluetooth.close()
        logger().info("Setting DUT as bt_slave....")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address, f"Unable to get bt_dut_address"
        logger().info("Advertising started on BT SLAVE device....DUT")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address, f"Unable to get bt_client_address"
        logger().info("Started BT in MASTER device....bt_client")
        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=6)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server) as bt_server_socket:
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
                enable_ps = wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_ps, "Unable to enable power save"
                enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2, power_save_type=RS9116PowerSaveProcedureTypes.FastPowerSave)
                assert enable_bt_ps, "Unable to enable bt power save"
                logger().info("DUT is on power save mode")

            # Send data from bt_client to dut
            logger().info("Sending data from bt_client to DUT.")
            with wifi_dut.interfaces.wifi.run_bt_task():
                sent = bt_server_socket.send(recv_text)  # SQA Agent is programmed to send back data
                logger().info(f"Data: '{recv_text}' sent from bt_client to DUT.....'{sent}'")
                assert sent, f"Not sent data from bt_client to DUT"
                data = bt_server_socket.recv()
                logger().info(f"Data received back from DUT is......'{data.decode()}'")
                assert data, f"Data not received back from DUT "
                assert data.decode() == recv_text
                logger().info(f"Send data from bt_client to dut is successful")

            # Send data from dut to bt_client
            logger().info("Sending data from DUT to bt_client.")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_server_socket.recv()
            logger().info(f"Data: '{send_text}' sent from DUT to bt_client.")
            logger().info(f"Data received back from bt_client is......'{data.decode()}'")
            assert data, f"Data not received back from bt_client"
            assert data.decode() == send_text
            logger().info(f"Send data from dut to bt_client is successful")

            # Ping dut
            logger().info("Pinging to DUT from bt_client")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info("Successfully pinged to DUT from bt_client")

            # returning value for closing the connection
            return bt_client_address, bt_server_socket, bt_dut_address

    if mode == "bt_master":
        # Initiating power save
        bt_client.interfaces.bluetooth.close()
        logger().info("Initiating power save on DUT")
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            wifi_dut.interfaces.wifi.set_sleep_gpio(True)
            wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
            wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

        logger().info("Setting DUT as bt_master....")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, f"Unable to get bt_dut_address"
        logger().info("Started BT in MASTER device....DUT")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address,  f"Unable to get bt_client_address"
        logger().info("Advertising started on SLAVE device....bt_client")
        time.sleep(3)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                               inquiry_duration_ms=20000, timeout=22, retry_counts=6)
        if not found:
            logger().warning(f"Dut unable to find the bt client device. The test case may fail.")

        with bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client) as bt_client_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_client_socket.create_client()
                logger().info(f"DUT Initiating bt connection with SLAVE device, this can take some time....")
                wifi_dut.interfaces.wifi.bt_connect(bt_client_address)
                addr = bt_client_socket.accept(timeout=120)
                assert addr == bt_dut_address
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
                assert data, f"Data not received back from DUT "
                assert data.decode() == recv_text
                logger().info(f"Send data from bt_client to dut is successful")

            # Send data from dut to bt_client
            logger().info("Sending data from DUT to bt_client.")
            wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
            data = bt_client_socket.recv()
            logger().info(f"Data: '{send_text}' sent from DUT to bt_client.")
            logger().info(f"Data received back from bt_client is......'{data.decode()}'")
            assert data, f"Data received back from bt_client"
            assert data.decode() == send_text
            logger().info("Send data from DUT to bt_client is successful.")

            # Ping dut
            logger().info("Pinging to DUT from bt_client")
            assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=bt_dut_address)
            logger().info("Successfully pinged to DUT from bt_client")

            # returning value for closing the connection
            return bt_client_address, bt_client_socket, bt_dut_address


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
        logger().info(f"Start scanning and connect to ble client")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=100)
        timeout = 200
        logger().info(f"connect")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)
        logger().info(f"Connect success")

    if mode == "ble_slave":
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        if start_needed:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to get ble_dut_address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(3)
        logger().info(f"Begin Scanning for BLE devices")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to get ble_client_address"
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
                       "supervision_timeout": 200}

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


def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=20)
    logger().info(f"Leave completed in {t.duration} seconds")


def run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    iperf_started = True
    net_perf_client.interfaces.net_perf.start()
    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)
        logger().info("Iperf throughput printed successfully")


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

    logger().info("Checking connection status of Wi-Fi")
    events = wifi_dut.interfaces.wifi.get_async_events()
    disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
    count_disconnect = set()
    if len(disconnect_events):
        count_disconnect.add(str(disconnect_events[0]))
        logger().info(f"Disconnect Events:{count_disconnect}")
        assert False, "DUT is not connected to Wi-Fi"
    assert len(disconnect_events) == 0
    logger().info("DUT is not disconnected from Wi-Fi")


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
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info(f"DUT successfully connected to {ble_client} Device...iteration: '{i}'")
        time.sleep(3)


class bt_spp_master_slave_thread(ThreadBase):
    def __init__(self, wifi_dut, bt_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.mode = mode

    def run(self):
        bt_spp_master_slave(self.wifi_dut, self.bt_client, self.mode)


class ble_master_slave_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        ble_master_slave(self.wifi_dut, self.ble_client, self.mode)


class wifi_traffic_thread(Thread):
    def __init__(self, net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip, iperf_time):
        super().__init__()
        self.net_perf_client = net_perf_client
        self.wifi_access_point = wifi_access_point
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.iperf_time = iperf_time

    def run(self):
        run_iperf_server(self.net_perf_client, self.wifi_access_point, self.wifi_dut, self.wifi_client, self.protocol, self.device_ip,
                         self.iperf_time)
        logger().info("Wi-Fi traffic thread completed")


class connect_disconnect_wifi_thread(Thread):
    def __init__(self, wifi_dut, wifi_access_point, iter_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.iter_count = iter_count

    def run(self):
        for i in range(1, self.iter_count + 1):
            time.sleep(5)
            logger().info(f"Initiating W-Fi disconnection on DUT...Iteration: '{i}'")
            wifi_leave(self.wifi_dut)
            logger().info(f"Successfully disconnected Wi-Fi from DUT...Iteration: '{i}'")
            time.sleep(2)
            logger().info(f"Re-Initiating W-Fi connection on DUT...Iteration: '{i}'")
            wifi_join(self.wifi_dut, self.wifi_access_point)
            logger().info(f"DUT successfully connected to Wi-Fi...Iteration: '{i}'")
        logger().info("Wi-Fi Connect-Disconnect thread completed")


class connect_disconnect_bt_thread(Thread):
    def __init__(self, wifi_dut, bt_client, bt_mode, bt_client_address, bt_dut_address, bt_socket, iter_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.iter_count = iter_count
        self.bt_client = bt_client
        self.bt_address = bt_client_address
        self.bt_socket = bt_socket
        self.bt_mode = bt_mode
        self.bt_dut_address = bt_dut_address
        self.iter_count = iter_count

    def run(self):
        time.sleep(10)

        logger().info("Initiating BT disconnection on DUT")
        for i in range(1, self.iter_count):
            logger().info(f"Initiating BT disconnection on DUT...iteration: '{i}'")
            self.bt_client.interfaces.bluetooth.disconnect(self.bt_address)
            #self.wifi_dut.interfaces.wifi.bt_disconnect(self.bt_address)
            time.sleep(3)
            logger().info(f"BT disconnection success...iteration: '{i}'")

            logger().info(f"Re-Initiating BT connection on DUT...iteration: '{i}'")
            self.wifi_dut.interfaces.wifi.bt_connect(self.bt_address, timeout=20)
            time.sleep(3)
            logger().info(f"BT connection success...iteration: '{i}'")
        logger().info("BT Connect-Disconnect thread completed")


class connect_disconnect_ble_thread(Thread):
    def __init__(self, wifi_dut, ble_client, ble_client_address, iter_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.iter_count = iter_count

    def run(self):
        connect_disconnect_ble(self.wifi_dut, self.ble_client, self.ble_client_address, self.iter_count)


# Verify STA_BT_BLE functionality when BT and BLE in SLAVE mode and Wi-Fi in STA mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_bt_ble_as_slave_C20075(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                           net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    # with bt_spp_master_slave_thread(wifi_dut, bt_client, mode="bt_slave"), ble_master_slave_thread(wifi_dut, ble_client, mode="ble_slave"):
    #     time.sleep(15)

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_address: '{bt_address}', bt_socket: '{bt_socket}'")

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_address}'")

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)

    logger().info("Initiating BT reset on DUT")
    bt_client.interfaces.bluetooth.bt_adapter.reset()
    wifi_dut.interfaces.wifi.bt_deinit()


# Verify STA_BT_BLE functionality when BT and BLE in MASTER mode and Wi-Fi in STA mode
# Need to re-look as bt_master mode test is failing.
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect", "bt_disconnect"])
def test_sta_bt_ble_connection_with_bt_ble_as_master_C20076(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                            net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_master"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)
    wifi_dut.interfaces.wifi.bt_deinit()


# Verify STA_BT_BLE functionality when BT in SLAVE mode, BLE in DUAL_ROLE and Wi-Fi in STA mode
# UTF-1282: Issue occurring while second test trying to create the RPC server when using 2 raspberry pi in the setup
# C20075 ---> one BT client and BLE-client is required. [So one is primary and other is secondary raspi]
# C20077 ---> required 2 ble clients itself [ble_client1 is primary raspi and ble_client2 is secondary raspi]
# In this case , for C20077 test case getting issue while Creating RPC server.
@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", ])
def test_sta_bt_ble_connection_with_ble_as_dual_role_C20077(wifi_dut, bt_client, ble_clients, wifi_access_point,
                                                            net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    logger().info("Initiating power save on DUT")
    if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        wifi_dut.interfaces.wifi.set_sleep_gpio(True)
        wifi_dut.interfaces.wifi.power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
        wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)


# Verify the connection stability of STA_BT_BLE devices while all the devices are connected and data transfer is happening
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_sta_bt_ble_connection_stability_C20078(wifi_dut, bt_client, ble_client, wifi_access_point, net_perf_client,
                                                wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)

    logger().info("Checking connection status of BT, BLE, Wi-Fi and keeping the setup undisturbed for 60 seconds")
    time.sleep(60)
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify the http download functionality of STA while BT and BLE are connected with remote devices and data transfer (SPP Rx and notifications are enabled).
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_http_download_C20079(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                         http_server, http_client, index_path):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    wifi_join(wifi_dut, wifi_access_point)

    # starts the dhcp in dut
    time.sleep(5)
    wifi_dut.interfaces.wifi.start_ip()

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_address: '{bt_address}', bt_socket: '{bt_socket}'")

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_address}'")

    logger().info("Enabling the wifi power save in dut")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    logger().info("Enabling the bt power save in dut")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi

    # API used to get the https data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

    logger().info(status)
    logger().info(content)
    assert content == content1, f"http send and receive content is not same"

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify the DUAL_MODE functionality if STA_BT_BLE while all the devices are connected and data transfer is in progress
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_dual_mode_functionality_C20080(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                                   net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify STA connect and disconnect functionality while BT and BLE are connected with remote devices and data transfer is happening.
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_sta_connect_disconnect_C20081(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                                  net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}' and Wi-Fi Connect-Disconnect thread")
    t1 = wifi_traffic_thread(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t2 = connect_disconnect_wifi_thread(wifi_dut, wifi_access_point, iter_count=5)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify BT connect and disconnect multiple times while STA and BLE are connected with remote devices and data transfer is in progress.
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_bt_connect_disconnect_C20082(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                                 net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}' and BT Connect-Disconnect thread")
    t1 = wifi_traffic_thread(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t2 = connect_disconnect_bt_thread(wifi_dut, bt_client, bt_mode, bt_address, bt_dut_address, bt_socket, iter_count=5)
    # ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
    t1.start()
    t2.start()

    t1.join()
    t2.join()

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)


# Verify BLE connect and disconnect multiple times while STA and BT are connected with remote devices and data transfer is in progress
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_ble_connect_disconnect_C20083(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                                  net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}' and BLE Connect-Disconnect thread")
    t1 = wifi_traffic_thread(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip, iperf_time=200)
    t1.start()
    logger().info(f"Initiating BLE Connect-Disconnect thread")
    connect_disconnect_ble(wifi_dut, ble_client, ble_address, iter_count=5)
    t1.join()

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify Power save 2 functionality of DUT when configured in STA_BT_BLE mode. Check if connectivity and data transfer is functional.
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_powersave_mode2_C20084(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                           net_perf_client, wifi_client, protocol, wifi_sniffer):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    # Get IP over DHCP
    wifi_dut.interfaces.wifi.start_ip()

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"*****Enable Enhanced Max Power save in DUT******")
    # Initiating power save2
    wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    assert result, "Power save is not enabled"
    time.sleep(3)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)
    time.sleep(10)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify the BG-SCAN functionality of STA when BT and BLE are connected to remote devices and data transfer is happening in STA_BT_BLE mode
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_bg_scan_C20085(wifi_dut, wifi_sniffer, bt_client, ble_client, wifi_access_point,
                                                   net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    validation = True
    logger().info("Verify RSI_STA connectivity by enabling BG scan")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_C20085')

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)

    # Validating probe request broadcast packet
    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                     f'and wlan.da == ff:ff:ff:ff:ff:ff'

    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
        'Unable to find probe request broadcast packet'

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify the functionality of DUT when we bringup and connect RSI_BT and RSI_BLE with remote devices first and then initiate RSI_STA scan and connect to AP in STA_BT_BLE mode.
#@pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20086'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("ssid", ['test_C20086'])
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_sta_scan_mode_C20086(wifi_dut, bt_client, ble_client, wifi_access_point,
                                                         net_perf_client, wifi_client, protocol, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_address: '{bt_address}', bt_socket: '{bt_socket}'")

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_address}'")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"Scan list is empty"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip)

    logger().info("Checking connection status of BT, BLE, Wi-Fi")
    check_connection_status(wifi_dut)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)


# Verify the Deep Sleep functionality of DUT when configured in STA_BT_BLE mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_bt_ble_connection_with_deep_sleep_functionality_C20087(wifi_dut, bt_client, ble_client, wifi_access_point):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Failed to fetch device ip"

    bt_mode = "bt_slave"
    logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
    bt_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
    logger().info(f"bt_address: '{bt_address}', bt_socket: '{bt_socket}'")

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_address}'")

    logger().info("Initiating power-save2 on DUT")
    result = wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(power_save_mode=RS9116PowerSaveModes.PowerSaveMode2)
    assert result, "Device has not gone to powersave mode"

    logger().info("Initiating BT disconnection on DUT")
    bt_disconnect(wifi_dut, bt_address, bt_socket)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_address)


