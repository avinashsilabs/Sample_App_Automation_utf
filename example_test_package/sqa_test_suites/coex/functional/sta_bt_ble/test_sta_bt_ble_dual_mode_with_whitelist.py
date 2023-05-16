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
from utf.utils.iperf.iperf_utils import ping
from retry import retry
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs

ping_count = 30

"""
    Setup Requirement: DUT(RS9116) , EFR32, 3 Raspberry PI required ,
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by cg team : Rashmi & team
    Description: STA_BT_BLE Test cases
"""


def logger():
    return get_logger(__name__)


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def wifi_join(wifi_dut, wifi_access_point, power_save=True):
    time.sleep(5)
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    device_ip = None
    for ip_count in range(5):
        try:
            result = wifi_dut.interfaces.wifi.start_ip(timeout=60)
            assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            break
        except Exception as err:
            logger().info(f"IP setting in DUT is failed...retry_count:{ip_count + 1}\nException:{err}")
            time.sleep(100)
    assert device_ip, "Failed to fetch DUT ip address"

    if power_save:
        enable_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_ps, "failed to enable WLAN power save"
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"

    logger().info("Pinging to DUT after power save")
    status = False
    for retry_count in range(5):
        try:
            logger().info(f'DUT ip {device_ip}')
            logger().info("pinging to dut.....")
            status = ping(device_ip, ping_count)
            assert status, "DUT not responding for ping request......"
            logger().info("ping to DUT is successful....")
            break
        except Exception as err:
            logger().info(f"Failed to ping to DUT...retry_count{retry_count + 1}\nException:{err}")
            time.sleep(15)
    assert status, "DUT not responding for ping request......"
    return device_ip


@retry(Exception, delay=15, tries=3)
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
        bt_server_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            logger().info(f"DUT initiating bt connection with SLAVE device, this can take some time....")
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected, "Unable to connect to DUT from raspi device"
            time.sleep(10)
        logger().info(f"bt_client:' {bt_client_address}' Successfully connected to DUT: '{bt_dut_address}'")

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
        logger().info("Setting DUT as bt_master....")
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
        assert bt_dut_address, f"Unable to get bt_dut_address"
        time.sleep(3)
        logger().info("Started BT in MASTER device....DUT")
        bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
        assert bt_client_address, f"Unable to get bt_client_address"
        logger().info("Advertising started on SLAVE device....bt_client")
        time.sleep(5)

        found = wifi_dut.interfaces.wifi.bt_inquiry_for_device(bt_client_address=bt_client_address, inquiry_type=2,
                                                               inquiry_duration_ms=20000, timeout=22, retry_counts=6)
        if not found:
            logger().warning(f"DUT unable to find the bt client device")
        assert found, "Dut unable to find the bt client device"
        bt_client_socket = bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Client)

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


@retry(Exception, delay=15, tries=3)
def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True):
    ble_client_address = None
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
            time.sleep(3)
            logger().info(f"Begin Scanning for BLE devices")
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"Unable to get ble_client_address"
            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_scanning()
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"ble_scan_list:\n{found_devices}")
            assert wifi_dut.interfaces.wifi.ble_address in found_devices, "Unable to find our DUT"
            assert (found_devices[
                        wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
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


def http_download(wifi_dut, http_server, http_client, index_path):
    http_server.interfaces.http.interface = "eth0"
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    # API used to get the https data
    status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path, timeout=500,
                                                        skip_data_print=0)
    status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)
    assert content == content1, "http server file content and downloaded file contents are not same"


def bt_disconnect(wifi_dut, bt_client_address, bt_socket):
    # Close BT connection
    wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
    bt_socket.close()
    time.sleep(3)
    logger().info("Successfully disconnected from BT SLAVE Device")


def ble_disconnect(wifi_dut, ble_client_address):
    # Ble disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")


@retry(Exception, delay=30, tries=5)
def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=30)
    logger().info(f"Leave completed in {t.duration} seconds")


def run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    time.sleep(3)
    net_perf_client.interfaces.net_perf.start()
    time.sleep(5)
    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    time.sleep(10)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)
        logger().info("Iperf throughput printed successfully")


def check_connection_status(wifi_dut, bt=True, ble=True, wlan=True, ble_clients=None, ble_dut_address=None):
    if bt:
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

    if ble:
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
                logger().info(f"\n************ Checking connection status of BLE from '{ble_client.name}' ************")
                status = ble_client.interfaces.bluetooth.get_connection_status(ble_dut_address)
                logger().info(f"Connection status in remote device '{ble_client.name}' is:{status}")
                assert status, f"Remote device '{ble_client.name}' is not connected to DUT '{ble_dut_address}'"
                logger().info(f"\n********** '{ble_client.name}' still connected to DUT '{ble_dut_address}' **********")

    if wlan:
        logger().info("\n******************** Checking connection status of Wi-Fi from DUT **********************")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, f"DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0, "DUT is disconnected from Wi-Fi"
        logger().info("\n************************** DUT is not disconnected from Wi-Fi **************************")


def connect_disconnect_ble(wifi_dut, ble_client, ble_dut_address, iter_count):
    for i in range(1, iter_count + 1):
        logger().info(f"Initiating BLE disconnection...iteration: '{i}'")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        logger().info(f"Disconnect completed...iteration: '{i}'")
        time.sleep(3)
        logger().info(f"Re-Initiating BLE connection...iteration: '{i}'")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to get ble_dut_address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(3)
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info(f"DUT successfully connected to {ble_client.name} Device...iteration: '{i}'")
        time.sleep(3)


def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()


def dut_clean_up(wifi_dut, ble_client_address=None, bt_client_address=None, bt_socket=None):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT ----------------------------")
    try:

        logger().info("BT disconnect from DUT")
        try:
            if bt_client_address:
                wifi_dut.interfaces.wifi.bt_disconnect(bt_client_address)
        except:
            pass
        if bt_socket:
            logger().info("Closing opened BT sockets in bt_client")
            bt_socket.close()
            time.sleep(5)
        logger().info("BLE disconnect from DUT")
        try:
            if ble_client_address:
                wifi_dut.interfaces.wifi.ble_disconnect(ble_client_address)
        except:
            pass
        time.sleep(5)
        logger().info("Closing all sockets opened in DUT")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(5)
    except Exception as err:
        logger().info(
            f"******* Exception occurred while cleaning up the DUT\nException is:{err}\nRecovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed ----------------------------")


@pytest.fixture()
def recovery(wifi_dut):
    try:
        wifi_dut.interfaces.wifi.init()
        time.sleep(5)
    except:
        wifi_dut.interfaces.wifi.reset_mode = "hard"
        wifi_dut.interfaces.wifi.reset()
        time.sleep(10)
        wifi_dut.interfaces.wifi.init()
        time.sleep(5)
    yield


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
        run_iperf_server(self.net_perf_client, self.wifi_dut, self.wifi_client, self.protocol,
                         self.device_ip, self.iperf_time)
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
            status = self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info(f"wifi_join status: {status}")
            time.sleep(5)
            logger().info(f"DUT successfully connected to Wi-Fi...Iteration: '{i}'")
        logger().info("Wi-Fi Connect-Disconnect thread completed")


class connect_disconnect_bt_thread(Thread):
    def __init__(self, wifi_dut, bt_client, bt_mode, bt_client_address, bt_dut_address, bt_socket, iter_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.iter_count = iter_count
        self.bt_client = bt_client
        self.bt_client_address = bt_client_address
        self.bt_socket = bt_socket
        self.bt_mode = bt_mode
        self.bt_dut_address = bt_dut_address
        self.iter_count = iter_count

    def run(self):
        time.sleep(10)
        logger().info("Initiating BT disconnection from remote device")
        for i in range(1, self.iter_count + 1):
            logger().info(f"\n\nInitiating BT disconnection from raspi device...iteration: '{i}'")
            self.bt_client.interfaces.bluetooth.bt_device.disconnect_device(self.bt_dut_address)
            self.bt_socket.close()
            logger().info("Waiting for some time to complete bt disconnection")
            time.sleep(10)
            logger().info(f"BT disconnection success...iteration: '{i}'")

            logger().info(f"\nRe-Initiating BT connection from raspi device...iteration: '{i}'")
            bt_server_socket = self.bt_client.interfaces.bluetooth.bt_socket(mode=BTSocketRole.Server)
            # SPP Connection
            with self.wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                logger().info(f"Raspi device initiating bt connection with DUT, this can take some time....")
                connected = bt_server_socket.connect(dest_mac_addr=self.bt_dut_address, retry_counts=10)
                assert connected, "Unable to connect to DUT from raspi device"
                time.sleep(10)
            logger().info(
                f"bt_client:' {self.bt_client.name}' Successfully connected to DUT: '{self.bt_dut_address}'")
            self.bt_socket = bt_server_socket
            logger().info(f"BT connection success...iteration: '{i}'")
            # Ping dut
            # logger().info("Pinging to DUT from raspi device")
            # assert self.bt_client.interfaces.bluetooth.bt_adapter.l2ping(dest_addr=self.bt_dut_address)
            # logger().info(f"Successfully pinged to DUT from bt_client....iteration: '{i}'")
            time.sleep(5)
        logger().info("BT Connect-Disconnect thread completed")


pytestmark = [pytest.mark.bt_client("raspi_bt_client"), pytest.mark.ble_client("secondary_raspi_ble_client"),
              pytest.mark.firmware_app("test_coex_custom")]


# Verify STA_BT_BLE functionality when BT and BLE in SLAVE mode and Wi-Fi in STA mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_bt_ble_as_slave_C20075(firmware_loader, wifi_sniffer, recovery, wifi_dut, bt_client,
                                                           ble_client, wifi_client, wifi_access_point, net_perf_client,
                                                           protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_connection_C20075.log_{int(time.time())}"):
            bt_socket = None
            bt_client_address = None
            ble_client_address = None
            validation = True
            testcase = "test_sta_bt_ble_connection_with_bt_ble_as_slave_C20075"
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
            time.sleep(3)

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Null frame with pm bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify STA_BT_BLE functionality when BT and BLE in MASTER mode and Wi-Fi in STA mode
# Need to re-look as bt_master mode test is failing.
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_bt_ble_as_master_C20076(firmware_loader, recovery, wifi_dut, bt_client,
                                                            wifi_access_point, ble_client, net_perf_client, wifi_client,
                                                            protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_connection_C20076.log_{int(time.time())}"):

            bt_socket = None
            bt_client_address = None
            ble_client_address = None
            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"

            bt_mode = "bt_master"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify STA_BT_BLE functionality when BT in SLAVE mode, BLE in DUAL_ROLE and Wi-Fi in STA mode
# UTF-1282: Issue occurring while second test trying to create the RPC server when using 2 raspberry pi in the setup
# C20075 ---> one BT client and BLE-client is required. [So one is primary and other is secondary raspi]
# C20077 ---> required 2 ble clients itself [ble_client1 is primary raspi and ble_client2 is secondary raspi]
# In this case , for C20077 test case getting issue while Creating RPC server.
# @pytest.mark.skip()
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_ble_as_dual_role_C20077(firmware_loader, recovery, wifi_dut, wifi_access_point,
                                                            bt_client, ble_clients, net_perf_client, wifi_client,
                                                            protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, "Minimum 2 raspi should be present in ble_clients section for this testcase"
    for ble_client in ble_clients:
        if str(ble_client.name).split('_')[0] == str(bt_client.name).split('_')[0]:
            message = "Same raspi device is used in bt_client and ble_clients, this is not supported. Please use 3 different raspi's for this testcase"
            logger().error(message)
            pytest.xfail(message)
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20077.log_{int(time.time())}"):
            ble_client1 = ble_clients[0]
            ble_client2 = ble_clients[1]
            bt_socket = None
            bt_client_address = None
            ble_client_address2 = None

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address1}', ble_dut_address:'{ble_dut_address}'")

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address2, ble_dut_address = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address,
                                                                    start_needed=False)

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut, ble_clients=ble_clients, ble_dut_address=ble_dut_address)

            logger().info(f"Disconnect from Remote device which is Master")
            ble_client1.interfaces.bluetooth.disconnect(ble_dut_address)
            time.sleep(10)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address2, bt_client_address, bt_socket)


# Verify the connection stability of STA_BT_BLE devices while all the devices are connected and data transfer is happening
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_stability_C20078(firmware_loader, wifi_sniffer, recovery, wifi_dut, bt_client,
                                                ble_client, wifi_access_point, net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_stability_C20078"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20078.log_{int(time.time())}"):

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip,
                             iperf_time=100)

            logger().info(
                "Checking connection status of BT, BLE, Wi-Fi and keeping the setup undisturbed for 60 seconds")
            time.sleep(60)
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Unable to find Null frame with pm bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
                'packet_count'], 'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify the http download functionality of STA while BT and BLE are connected with remote devices and data transfer (SPP Rx and notifications are enabled).
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.bt_classic
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_http_download_C20079(firmware_loader, wifi_sniffer, recovery, wifi_dut, bt_client,
                                                         ble_client, http_server, wifi_access_point, http_client,
                                                         index_path):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20079.log_{int(time.time())}"):
            testcase = "test_sta_bt_ble_connection_with_http_download_C20079"
            bt_socket = None
            bt_client_address = None
            ble_client_address = None
            validation = True
            logger().info("configuring the Sniffer with the channel")
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            logger().info("start capturing with Sniffer by giving the test case name as filename")
            wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
            time.sleep(3)

            logger().info("Joining into Wi-Fi")
            wifi_join(wifi_dut, wifi_access_point)
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            http_server.interfaces.http.interface = "eth0"
            wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
            # API used to get the https data
            status, content = wifi_dut.interfaces.http.http_get(http_server.interfaces.http, index_path)
            status1, content1 = http_client.interfaces.http.http_get(http_server.interfaces.http, index_path)

            logger().info(status)
            logger().info(content)
            assert content == content1, f"http send and receive content is not same"

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find Null frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify the DUAL_MODE functionality if STA_BT_BLE while all the devices are connected and data transfer is in progress
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_dual_mode_functionality_C20080(firmware_loader, wifi_sniffer, recovery, wifi_dut,
                                                                   wifi_access_point, ble_client, net_perf_client,
                                                                   bt_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_with_dual_mode_functionality_C20080"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20080.log_{int(time.time())}"):
            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find Null frame with PM bi set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify STA connect and disconnect functionality while BT and BLE are connected with remote devices and data transfer is happening.
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_sta_connect_disconnect_C20081(firmware_loader, wifi_sniffer, recovery,
                                                                  wifi_access_point, wifi_dut, ble_client, bt_client,
                                                                  net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_with_sta_connect_disconnect_C20081"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20081.log_{int(time.time())}"):
            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_master"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(
                f"Initiating {protocol} traffic with client '{wifi_client.name}' and Wi-Fi Connect-Disconnect thread")
            t1 = wifi_traffic_thread(net_perf_client, wifi_access_point, wifi_dut, wifi_client, protocol, device_ip,
                                     iperf_time=100)
            t2 = connect_disconnect_wifi_thread(wifi_dut, wifi_access_point, iter_count=5)

            t1.start()
            time.sleep(5)
            t2.start()

            t1.join()
            t2.join()

            logger().info("Checking connection status of BT, BLE")
            check_connection_status(wifi_dut, wlan=False)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find NULL frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify BT connect and disconnect multiple times while STA and BLE are connected with remote devices and data transfer is in progress.
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.bt_classic
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_bt_connect_disconnect_C20082(firmware_loader, wifi_sniffer, recovery, wifi_dut,
                                                                 wifi_access_point, ble_client, bt_client, http_client,
                                                                 http_server, index_path):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_with_bt_connect_disconnect_C20082"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20082.log_{int(time.time())}"):
            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")
            time.sleep(5)

            logger().info("Initiating http_download and BT Connect-Disconnect thread")
            t1 = Thread(target=http_download, args=(wifi_dut, http_server, http_client, index_path))
            t2 = connect_disconnect_bt_thread(wifi_dut, bt_client, bt_mode, bt_client_address, bt_dut_address,
                                              bt_socket, iter_count=5)

            t1.start()
            t2.start()

            t1.join()
            t2.join()

            logger().info("Checking connection status of BLE, Wi-Fi")
            check_connection_status(wifi_dut, bt=False)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find NULL Frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify BLE connect and disconnect multiple times while STA and BT are connected with remote devices and data transfer is in progress
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem"
    },
)
@pytest.mark.bt_classic
@pytest.mark.http_server("raspi_lighttpd_tls")
@pytest.mark.parametrize("index_path", {"1MB.htm"})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_ble_connect_disconnect_C20083(firmware_loader, wifi_sniffer, recovery, wifi_dut,
                                                                  wifi_access_point, ble_client, bt_client, http_client,
                                                                  http_server, index_path):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_with_ble_connect_disconnect_C20083"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20083.log_{int(time.time())}"):

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")
            time.sleep(10)

            logger().info("Initiating http_download and BLE Connect-Disconnect thread")
            t1 = Thread(target=http_download, args=(wifi_dut, http_server, http_client, index_path))
            t2 = Thread(target=connect_disconnect_ble, args=(wifi_dut, ble_client, ble_dut_address, 5))

            t1.start()
            t2.start()

            t1.join()
            t2.join()

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find NULL frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify Power save 2 functionality of DUT when configured in STA_BT_BLE mode. Check if connectivity and data transfer is functional.
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_powersave_mode2_C20084(firmware_loader, recovery, wifi_dut, bt_client, wifi_sniffer,
                                                           wifi_access_point, net_perf_client, wifi_client, ble_client,
                                                           protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C4004.txt')
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20084.log_{int(time.time())}"):
            bssid = wifi_access_point.interfaces.wifi.bssid
            logger().info(f'AP BSSID = {bssid}')

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)
            time.sleep(10)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            # validate NULL data frame with PM bit set to '1'
            packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                             f'and (wlan.da == {bssid}))'

            logger().info('Validation for NULL packet with pm bit 1')
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify the BG-SCAN functionality of STA when BT and BLE are connected to remote devices and data transfer is happening in STA_BT_BLE mode
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_bg_scan_C20085(firmware_loader, recovery, wifi_sniffer, bt_client, net_perf_client,
                                                   wifi_access_point, ble_client, wifi_dut, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("Verify RSI_STA connectivity by enabling BG scan")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_bgscan_C20085')
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20085.log_{int(time.time())}"):

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"

            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("Stop Sniffer finally")
            wifi_sniffer.interfaces.capture.stop_capture()

            # Validating probe request broadcast packet
            packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                             f'wlan.sa == {dut_mac_address} and wlan.fc.type_subtype == 0x0004 ' \
                             f'and wlan.da == ff:ff:ff:ff:ff:ff'
            packet_filter2 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter3 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'

            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find probe request broadcast packet'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find NULL frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify the functionality of DUT when we bringup and connect RSI_BT and RSI_BLE with remote devices first and then initiate RSI_STA scan and connect to AP in STA_BT_BLE mode.
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.ble_client("secondary_raspi_ble_client")
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_sta_scan_mode_C20086(firmware_loader, recovery, wifi_sniffer, wifi_dut, bt_client,
                                                         wifi_access_point, ble_client, net_perf_client, wifi_client,
                                                         protocol, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_with_sta_scan_mode_C20086"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20086.log_{int(time.time())}"):
            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            with TimeMeasurer() as t:
                scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid,
                                                             channel=wifi_access_point.interfaces.wifi.channel)
            logger().info(scan_results)
            assert len(scan_results) > 0, f"Scan list is empty"
            logger().info(f"Scan in {t.duration} seconds")

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip,
                             iperf_time=60)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find Null frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)


# Verify the Deep Sleep functionality of DUT when configured in STA_BT_BLE mode
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.ble_client("secondary_raspi_ble_client")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
@pytest.mark.bt_classic
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_sta_bt_ble_connection_with_deep_sleep_functionality_C20087(firmware_loader, wifi_sniffer, recovery, bt_client,
                                                                    wifi_access_point, ble_client, net_perf_client,
                                                                    wifi_client, wifi_dut, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        testcase = "test_sta_bt_ble_connection_with_deep_sleep_functionality_C20087"
        bt_socket = None
        bt_client_address = None
        ble_client_address = None
        validation = True
        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_sta_bt_ble_C20087.log_{int(time.time())}"):
            # Enables the wifi power save in DUT
            logger().info("Setting DUT in wlan power save...")
            enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)
            assert enable_wifi_ps, "Failed to enable wifi power save8 in DUT"
            # Enables the bt power save in DUT
            logger().info("Setting DUT in bt power save...")
            enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)
            assert enable_bt_ps, "Failed to enable bt power save8 in DUT"

            logger().info("Initiating scan from dut...")
            scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(f'Scan results are : {scan_results}')

            logger().info("Joining into Wi-Fi")
            device_ip = wifi_join(wifi_dut, wifi_access_point, power_save=False)
            assert device_ip, "Failed to fetch device ip"
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            bt_mode = "bt_slave"
            logger().info(f"Initiating BT test with DUT mode '{bt_mode}'")
            bt_client_address, bt_socket, bt_dut_address = bt_spp_master_slave(wifi_dut, bt_client, bt_mode)
            logger().info(
                f"bt_dut_address:'{bt_dut_address}', bt_client_address:'{bt_client_address}'\nbt_socket:'{bt_socket}'")

            ble_mode = "ble_slave"
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f"ble_client_address:'{ble_client_address}', ble_dut_address:'{ble_dut_address}'")

            logger().info(f"Initiating '{protocol}' traffic with client '{wifi_client.name}'")
            run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

            logger().info("Checking connection status of BT, BLE, Wi-Fi")
            check_connection_status(wifi_dut)

            logger().info("stopping capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f' (wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address})) '
            packet_filter2 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a)'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find NULL Frame with PM bit set in sniffer capture'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
                'Unable to find ps polls in sniffer capture'
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address, bt_client_address, bt_socket)
