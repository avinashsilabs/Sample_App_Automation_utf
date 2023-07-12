import re
import time
from random import randint
from datetime import datetime, timedelta
import datetime
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.wifi import WlanError
from utf.utils.stopwatch import Stopwatch
from utf.utils.thread_base import ThreadBase
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict, ping
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from numpy import arange
import random
import string
from utf.interfaces.bluetooth import BLEDeviceState
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116DataRate, RS9116RejoinParams, RS9116JoinFeatureBitMap, \
    RS9116PowerSaveProcedureTypes, RS9116ExtCustomFeatureBitMap, RS9116BTFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants,

)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def dut_clean_up(wifi_dut):
    logger().info("\n\n ########## Cleaning UP the DUT ###########")
    try:
        logger().info("BLE disconnect from DUT")
        for device_address in wifi_dut.interfaces.wifi.bt_devices_address:
            try:
                wifi_dut.interfaces.wifi.bt_disconnect(device_address)
            except:
                pass
        logger().info("Closing all opened sockets")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        time.sleep(3)
    except:
        logger().info("******* Recovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info("\n *********** Cleaning UP of DUT is Completed ***********")

def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()


class spp_loopback(ThreadBase):
    def __init__(self, bt_server_socket, wifi_dut, recv_text, logger):
        super().__init__()
        self.bt_server_socket = bt_server_socket
        self.wifi_dut = wifi_dut
        self.recv_text = recv_text
        self.timeout = logger

    def run(self):
        # Sending BT data for 80 seconds
        recv_text = text_generator(size=30)
        time.sleep(5)
        sw = Stopwatch()
        logger().info(f"BT DATA transfer for 80 seconds")
        while sw.elapsed_sec < 80:
            # thread_lock.acquire()
            time.sleep(0.5)
            sent = self.bt_server_socket.send(
                recv_text
            )  # Dut is programmed to send back data

            assert sent
            data = self.bt_server_socket.recv(timeout=10)
            assert data is not None
            assert data.decode() == recv_text


class spp_loopback_ssl(ThreadBase):
    def __init__(self, bt_server_socket, wifi_dut, recv_text, logger):
        super().__init__()
        self.bt_server_socket = bt_server_socket
        self.wifi_dut = wifi_dut
        self.recv_text = recv_text
        self.timeout = logger

    def run(self):
        recv_text = text_generator(size=30)
        time.sleep(5)
        sw = Stopwatch()
        logger().info(f"BT DATA transfer for 25 seconds")
        while sw.elapsed_sec < 25:
            time.sleep(0.5)
            sent = self.bt_server_socket.send(
                recv_text
            )  # Dut is programmed to send back data

            assert sent
            data = self.bt_server_socket.recv(timeout=10)
            assert data is not None
            assert data.decode() == recv_text


class BleThreadDisconnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, bt_cli_add):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.bt_client_address = bt_cli_add

    def run(self):
        self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address, timeout=30)
        # time.sleep(10)

class BleThreadConnection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode
        global bt_cli_add
        self.tcp_socket_obj = TcpIpSockets()
        if self.mode:
            # Start DUT BLE as a Master
            self.logger.info('***** DUT BLE as a Master *****')
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            time.sleep(5)
            assert self.bt_dut_address is not None

            # # Start ble client(Raspberry)
            self.bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(
                bt_dut_address=self.bt_dut_address)
            bt_cli_add = self.bt_client_address
            assert self.bt_client_address is not None

            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.bt_client_address, timeout=15)
            time.sleep(10)

        elif self.mode is False:
            self.logger.info('***** DUT BLE as a Slave *****')
            # Set up DUT for BLE advertising
            self.bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert self.bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.bt_dut_address)
            assert bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                    == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )

    def run(self):
        if self.mode:
            # for i in range(0, 5):
            #     self.logger.info('***** DUT BLE as a Master *****')
            #     self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.bt_client_address, timeout=30)
            #     time.sleep(10)
            #
            #     self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address, timeout=30)
            #     time.sleep(10)

            self.logger.info('***** DUT BLE as a Master *****')
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=self.bt_client_address, timeout=30)
            # time.sleep(10)
            #
            # self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=self.bt_client_address, timeout=30)
            # time.sleep(10)

        elif self.mode is False:
            self.logger.info('********* DUT BLE as a Slave **********')
            self.ble_client.interfaces.bluetooth.connect(self.bt_dut_address)
            time.sleep(10)
            if self.connect_disconnect:
                self.ble_client.interfaces.bluetooth.disconnect(self.bt_dut_address)

class WifiJoinThreadForTx(ThreadBase):
    def __init__(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip, counter=None):
        super().__init__()
        self.iperf_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.counter = counter

    def run(self):
        if self.counter is not None:
            for i in range(0, self.counter):
                # start_iperf_dut_as_client(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip)
                self.iperf_obj.start_iperf_dut_as_server(self.wifi_dut, self.wifi_client, self.net_perf_client,
                                                         self.protocol,
                                                         self.device_ip)
        else:
            self.iperf_obj.start_iperf_dut_as_server(self.wifi_dut, self.wifi_client, self.net_perf_client,
                                                     self.protocol, self.device_ip)

class WifiJoinThreadForRx(ThreadBase):
    def __init__(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip, counter=None):
        super().__init__()
        self.iperf_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.counter = counter

    def run(self):
        if self.counter is not None:
            for i in range(0, self.counter):
                # start_iperf_dut_as_client(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip)
                self.iperf_obj.start_iperf_dut_as_client(self.wifi_dut, self.wifi_client, self.net_perf_client, self.protocol,
                                                         self.device_ip)
        else:
            self.iperf_obj.start_iperf_dut_as_client(self.wifi_dut, self.wifi_client, self.net_perf_client, self.protocol, self.device_ip)


class BtSppThreadConnectionDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, bt_client, dut_as_master, data_transfer=False):
        super().__init__()
        self.connect_data_trans_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client
        self.data_transfer = data_transfer
        self.dut_as_master = dut_as_master

    def run(self):
        self.connect_data_trans_obj.connection_bt_spp_master_slave(self.wifi_dut, self.bt_client, self.dut_as_master,
                                                                   self.data_transfer)

class BleThreadConnectionDataTransfer(ThreadBase):
    def __init__(self, wifi_dut, ble_client, data1):
        super().__init__()
        self.connect_data_trans_obj = FilterPacket()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.data1 = data1

    def run(self):
        self.connect_data_trans_obj.test_ble_wlan_transfer_server_slave(self.wifi_dut, self.ble_client, self.data1)


class WifiPingThread(ThreadBase):
    def __init__(self, wifi_dut, device_ip):
        super().__init__()
        self.device_ip = device_ip

    def run(self):
        # Initiate ping from third party wifi-client to DUT
        ping(self.device_ip, 150)
        time.sleep(10)

class FilterPacket:
    def connection_bt_spp_master_slave(self, wifi_dut, bt_client, dut_as_master=True,
                                       data_transfer=False):
        with TimeMeasurer() as t:
            if dut_as_master:
                bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_master_spp()
                assert bt_dut_address is not None

                bt_client_address = bt_client.interfaces.bluetooth.start_spp_slave(bt_dut_address, pin_code)
                assert bt_client_address is not None
                time.sleep(0.5)

                # Added set class to 400100 to avoid [Errno 112] Host is down issue
                bt_client.interfaces.bluetooth.bt_adapter.set_class('400100')

                with bt_client.interfaces.bluetooth.bt_socket(
                        mode=BTSocketRole.Client
                ) as bt_client_socket:
                    # SPP Connection
                    with wifi_dut.interfaces.wifi.run_bt_task():
                        bt_client_socket.create_client()
                        result = ThreadBase.call_functions_simultaneously(
                            [(wifi_dut.interfaces.wifi.bt_connect, bt_client_address), (bt_client_socket.accept, 20)])
                        assert result[1] == bt_dut_address
                        logger().info(f"Result from Callable Function {result}")

                    # Check for data transfer
                    if data_transfer:
                        send_text = "sA0L9b1xEgGuUqN5YOlx" * 10
                        recv_text = "H2D7yZKRhKULU9Xil5Yv" * 10
                        # Send data from bt_client to dut
                        with wifi_dut.interfaces.wifi.run_bt_task():
                            sent = bt_client_socket.send(
                                recv_text
                            )  # Dut is programmed to send back data
                            assert sent
                            data = bt_client_socket.recv()
                            assert data is not None
                            assert data.decode() == recv_text

                        # Send data from dut to bt_client
                        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                        data = bt_client_socket.recv()
                        assert data is not None
                        assert data.decode() == send_text

                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                    # Close connection
                    bt_client_socket.close()
                    time.sleep(
                        0.2
                    )
                    client_address = bt_client_address
            elif dut_as_master is False:
                bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
                assert bt_dut_address is not None

                bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
                assert bt_client_address is not None

                # Added set class to 400100 to avoid [Errno 112] Host is down issue
                bt_client.interfaces.bluetooth.bt_adapter.set_class('400100')

                with bt_client.interfaces.bluetooth.bt_socket(
                        mode=BTSocketRole.Server
                ) as bt_server_socket:
                    # SPP Connection
                    with wifi_dut.interfaces.wifi.run_bt_task():
                        bt_server_socket.create_server()
                        connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                        assert connected

                    if data_transfer:
                        send_text = "sA0L9b1xEgGuUqN5YOlx" * 10
                        recv_text = "H2D7yZKRhKULU9Xil5Yv" * 10
                        # Send data from bt_client to dut
                        with wifi_dut.interfaces.wifi.run_bt_task():
                            sent = bt_server_socket.send(
                                recv_text
                            )  # SQA Agent is programmed to send back data
                            assert sent
                            data = bt_server_socket.recv()
                            assert data is not None
                            assert data.decode() == recv_text

                        # Send data from dut to bt_client
                        wifi_dut.interfaces.wifi.bt_spp_transfer(send_text, bt_client_address)
                        data = bt_server_socket.recv()
                        assert data is not None
                        assert data.decode() == send_text

                    # Ping dut
                    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                        dest_addr=bt_dut_address
                    )

                    # Close connection
                    bt_server_socket.close()
                bt_client_address = bt_dut_address

        logger().info(f"Scan in {t.duration} seconds")
        logger().info(f"BT ADDRESS {bt_client_address} ")
        return bt_client_address

    def start_iperf_dut_as_server(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip, suspend_bt_task=0,
                                  suspend_ble_task=0, enable_async_socket=0, enable_socket_config=0):
        # # preparing iperf
        # device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

        # preparing iperf
        net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=protocol)

        # creating results object for sharing between host and dut
        result = Result(net_perf_client.interfaces.net_perf.protocol)

        # open socket and start listening
        with wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=net_perf_client.interfaces.net_perf.protocol,
                port=net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=net_perf_client.interfaces.net_perf.client_data_len,
                time=net_perf_client.interfaces.net_perf.client_timeout,
                suspend_bt_task=suspend_bt_task,
                suspend_ble_task=suspend_ble_task,
                enable_async_socket=enable_async_socket,
                enable_socket_config=enable_socket_config
        ) as obj:
            # start iperf
            net_perf_client.interfaces.net_perf.start()
            # capture device output
            wifi_dut.interfaces.wifi.read_from_device(obj, net_perf_client.interfaces.net_perf.client_timeout)

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output(result)
        if tp is not None:
            print_dict("##     ", tp)
        # assert tp is not None
        # __print_throughput(tp)

    def start_iperf_dut_as_client(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip, suspend_bt_task=0,
                                  suspend_ble_task=0):
        # device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        assert wifi_client.interfaces.wifi.ping(server_ip=device_ip)

        # starting iperf
        net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol)
        net_perf_client.interfaces.net_perf.start()

        # open socket and send traffic
        wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            net_perf_client.interfaces.net_perf.server_port,
            net_perf_client.interfaces.net_perf.protocol,
            net_perf_client.interfaces.net_perf.client_options,
            suspend_bt_task=suspend_bt_task,
            suspend_ble_task=suspend_ble_task
        )

        # get and print throughput
        tp = net_perf_client.interfaces.net_perf.process_output()
        # assert tp is not None
        # __print_throughput(tp)
        if tp is not None:
            print_dict("##     ", tp)

    def text_generator(size=200):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

    def test_ble_wlan_transfer_server_slave(self, wifi_dut, ble_client, data1):
        # if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        #     raise NotImplementedError(
        #         "This test case is only currently implemented for SAPI"
        #     )

        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        # data1 = "LzY0"
        # data2 = "K09x"
        # data3 = "Mx3Y"
        #
        # # Set up BLE Server on DUT
        # bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
        # assert bt_dut_address is not None
        # wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        # wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        # wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)
        #
        # # Start advertising
        # wifi_dut.interfaces.wifi.ble_start_advertising()
        #
        # # Begin Scanning for BLE devices
        # bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        # assert bt_client_address is not None
        #
        # device_found = False
        # sw = Stopwatch()
        # while sw.elapsed_sec < 30:
        #     found_devices = ble_client.interfaces.bluetooth.get_devices()
        #     if bt_dut_address in found_devices and \
        #             found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
        #         device_found = True
        #         break
        #
        # ble_client.interfaces.bluetooth.stop_scanning()
        # assert device_found
        #
        # # connecting to dut
        # ble_client.interfaces.bluetooth.connect(bt_dut_address)
        # time.sleep(1)

        # Get the state of the dut
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        # resolving charecteristic
        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
        assert len(servs) > 0
        assert len(chars) > 0

        char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                               service_uid=service_uid,
                                                                                               char_uid=char_uid)
        assert char_path is not None
        assert len(char_props) > 0

        # read value - Notifications not enabled
        result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)
        assert result == data1

        # subscribe to notifications
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(char_path=char_path, char_uid=char_uid)
        time.sleep(2)
        # notify only
        wifi_dut.interfaces.wifi.ble_notify_value()

        # subscribe to notifications
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(char_path=char_path)
        ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(1)
        # notify only - disabled notifications - should raise exception
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.ble_notify_value()
        assert exc_info.value.error_code == 0x21 or exc_info.value.error_code == 0xFFFFFFFD

        # assert received notifications
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(notifications)
        assert len(notifications) == 1
        assert notifications[0] == data1


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_standalone_tcp_rx_c20741(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_standalone_tcp_rx_c20741')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                  enable_async_socket=1, enable_socket_config=1)

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_standalone_tcp_tx_c20740(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_standalone_tcp_tx_c20740')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_standalone_udp_rx_c20739(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_standalone_udp_rx_c20739')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                  enable_async_socket=1, enable_socket_config=1)

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_standalone_udp_tx_c20738(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client,
                                       protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_standalone_udp_tx_c20738')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_connected_tcp_rx_c20751(wifi_sniffer, bt_client, bt_dut, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_tcp_rx_c20751')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                           tcp_tx_only_sockets=0,
                                           tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                           tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=10,
                                           tcp_rx_window_div_factor=10)

    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address is not None

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected

        ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                      suspend_bt_task=1, suspend_ble_task=1, enable_async_socket=1, enable_socket_config=0)
        logger().info(f"verifying BT connection after IPERF completion")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_connected_tcp_tx_c20750(wifi_sniffer, bt_client, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_tcp_tx_c20750')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address is not None

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected

        ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                      suspend_bt_task=1, suspend_ble_task=1)
        logger().info(f"verifying BT connection after IPERF completion")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_connected_udp_rx_c20749(wifi_sniffer, bt_client, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_udp_rx_c20749')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address is not None

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected

        ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                      suspend_bt_task=1, suspend_ble_task=1, enable_async_socket=1,
                                                      enable_socket_config=1
                                                      )
        logger().info(f"verifying BT connection after IPERF completion")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_connected_udp_tx_c20748(wifi_sniffer, bt_client, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_udp_tx_c20748')

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address is not None

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected

        ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
        iter_count = utf_constants.get("iter_count")
        for i in range(0, iter_count):
            filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                      suspend_bt_task=1, suspend_ble_task=1)
        logger().info(f"verifying BT connection after IPERF completion")
        assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            dest_addr=bt_dut_address
        )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_ble_connected_tcp_rx_c20747(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client,
                                          wifi_dut, net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    conn_params = {
        "min_conn_interval": utf_constants.get("min_conn_interval"),
        "max_conn_interval": utf_constants.get("max_conn_interval"),
        "conn_latency": 0,
        "supervision_timeout": utf_constants.get("supervision_timeout")}
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                           tcp_tx_only_sockets=0,
                                           tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                           tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=10,
                                           tcp_rx_window_div_factor=10)

    #logger().info("Setting the dut IO capability to display only.....")
  #bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    # Set up DUT for BLE advertising
    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch dut bd address...."

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address, min_conn_interval=conn_params["min_conn_interval"],
                                            max_conn_interval=conn_params["max_conn_interval"],
                                            conn_latency=conn_params["conn_latency"],
                                            supervision_timeout=conn_params["supervision_timeout"])

    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                  suspend_bt_task=1, suspend_ble_task=1, enable_async_socket=1,
                                                  enable_socket_config=1
                                                  )

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    time.sleep(2)
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    time.sleep(2)
    logger().info(f"DUT going to leave AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()



@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_ble_connected_tcp_tx_c20746(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut,
                                          net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    conn_params = {
        "min_conn_interval": utf_constants.get("min_conn_interval"),
        "max_conn_interval": utf_constants.get("max_conn_interval"),
        "conn_latency": 0,
        "supervision_timeout": utf_constants.get("supervision_timeout")}
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    #logger().info("Setting the dut IO capability to display only.....")
  #bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    # Set up DUT for BLE advertising
    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch dut bd address...."

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address, min_conn_interval=conn_params["min_conn_interval"],
                                            max_conn_interval=conn_params["max_conn_interval"],
                                            conn_latency=conn_params["conn_latency"],
                                            supervision_timeout=conn_params["supervision_timeout"])
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                  suspend_bt_task=1, suspend_ble_task=1)

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    time.sleep(2)
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    time.sleep(2)
    logger().info(f"DUT going to leave AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_ble_connected_udp_rx_c20745(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut,
                                          net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    conn_params = {
        "min_conn_interval": utf_constants.get("min_conn_interval"),
        "max_conn_interval": utf_constants.get("max_conn_interval"),
        "conn_latency": 0,
        "supervision_timeout": utf_constants.get("supervision_timeout")}
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    #logger().info("Setting the dut IO capability to display only.....")
  #bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    # Set up DUT for BLE advertising
    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch dut bd address...."

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address, min_conn_interval=conn_params["min_conn_interval"],
                                            max_conn_interval=conn_params["max_conn_interval"],
                                            conn_latency=conn_params["conn_latency"],
                                            supervision_timeout=conn_params["supervision_timeout"])
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                  suspend_bt_task=1, suspend_ble_task=1, enable_async_socket=1,
                                                  enable_socket_config=1
                                                  )

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    time.sleep(2)
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    time.sleep(2)
    logger().info(f"DUT going to leave AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_ble_connected_udp_tx_c20744(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut,
                                          net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    conn_params = {
        "min_conn_interval": utf_constants.get("min_conn_interval"),
        "max_conn_interval": utf_constants.get("max_conn_interval"),
        "conn_latency": 0,
        "supervision_timeout": utf_constants.get("supervision_timeout")}
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    #logger().info("Setting the dut IO capability to display only.....")
    # bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

    # Set up DUT for BLE advertising
    logger().info("Initiate ble service in DUT")
    bt_dut_address = bt_dut.interfaces.bluetooth.ble_start()
    assert bt_dut_address, "unable to fetch dut bd address...."

    logger().info("Set DUT in advertise mode")
    bt_dut.interfaces.bluetooth.ble_start_advertising()

    logger().info("Start smp scan from the remote device")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None
    time.sleep(5)
    logger().info("stop scanning ....")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    logger().info("Check the dut is listed...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert bt_dut.interfaces.bluetooth.ble_address in found_devices

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address, min_conn_interval=conn_params["min_conn_interval"],
                                            max_conn_interval=conn_params["max_conn_interval"],
                                            conn_latency=conn_params["conn_latency"],
                                            supervision_timeout=conn_params["supervision_timeout"])
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                  suspend_bt_task=1, suspend_ble_task=1)

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    time.sleep(2)
    bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address)
    time.sleep(2)
    logger().info(f"DUT going to leave AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "bt_disconnect"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_data_transfer_tcp_rx_c20759(wifi_sniffer, bt_client, bt_dut, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wlan_bt_data_transfer_tcp_rx_c20759.log_{int(time.time())}"):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_tcp_rx_c20751')

            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_dut.interfaces.wifi.start_ip()
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                                   tcp_tx_only_sockets=0,
                                                   tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                                   tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=10,
                                                   tcp_rx_window_div_factor=10)

            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None

            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
            assert found, "device not found"

            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                    assert connected
                    recv_text = "zvnpoinewnqflkwdnfvoiwnvkwln"
                    time.sleep(2)

                    spp_obj = spp_loopback(bt_server_socket, wifi_dut, recv_text, logger)
                    spp_obj.start()
                ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
                iter_count = utf_constants.get("iter_count")
                for i in range(0, iter_count):
                    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                              suspend_bt_task=0, suspend_ble_task=0, enable_async_socket=1,
                                                              enable_socket_config=1
                                                              )

                logger().info(f"verifying BT connection after IPERF completion")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )
                bt_server_socket.close()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        dut_clean_up(wifi_dut)
        raise

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "bt_disconnect"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_data_transfer_tcp_tx_c20758(wifi_sniffer, bt_dut, bt_client, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    try:
        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wlan_bt_data_transfer_tcp_tx_c20758.log_{int(time.time())}"):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_tcp_rx_c20751')
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_dut.interfaces.wifi.start_ip()
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None

            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
            assert found, "device not found"

            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                    assert connected
                    recv_text = "zvnoinewnqflkwdnfvoiwnvkwln"
                    time.sleep(2)

                    spp_obj = spp_loopback(bt_server_socket, wifi_dut, recv_text, logger)
                    spp_obj.start()
                ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
                iter_count = utf_constants.get("iter_count")
                for i in range(0, iter_count):
                    filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                              suspend_bt_task=0, suspend_ble_task=0)
                time.sleep(2)
                logger().info(f"verifying BT connection after IPERF completion")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

            bt_server_socket.close()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        dut_clean_up(wifi_dut)
        raise

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "bt_disconnect"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_data_transfer_udp_rx_c20757(wifi_sniffer, bt_client, bt_dut, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    try:

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wlan_bt_data_transfer_udp_rx_c20757.log_{int(time.time())}"):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_tcp_rx_c20751')

            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_dut.interfaces.wifi.start_ip()
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            time.sleep(2)
            logger().info("Fetching DUT fw version ")
            wifi_dut.interfaces.wifi.version()

            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None

            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
            assert found, "device not found"

            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                    assert connected
                    recv_text = "zvnoinewnqflkwdnfvoiwnvkwln"
                    time.sleep(2)

                    spp_obj = spp_loopback(bt_server_socket, wifi_dut, recv_text, logger)
                    spp_obj.start()

                    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
                iter_count = utf_constants.get("iter_count")
                for i in range(0, iter_count):
                    filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                              suspend_bt_task=0, suspend_ble_task=0, enable_async_socket=1,
                                                              enable_socket_config=1
                                                              )

                logger().info(f"verifying BT connection after IPERF completion")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )
                bt_server_socket.close()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        dut_clean_up(wifi_dut)
        raise

@pytest.mark.bt_classic
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "bt_disconnect"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake
    },
)
def test_wlan_bt_data_transfer_udp_tx_c20756(wifi_sniffer, bt_client, bt_dut, wifi_access_point, wifi_client, wifi_dut,
                                         net_perf_client, protocol, utf_constants):
    filter_pack_obj = FilterPacket()
    try:

        with BleLogs(start_collecting_logs=True,
                     bt_log_path=f"reports/test_wlan_bt_data_transfer_udp_tx_c20756.log_{int(time.time())}"):
            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_bt_connected_udp_tx_c20748')
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {dut_mac_address}")
            wifi_dut.interfaces.wifi.start_ip()
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

            bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
            assert bt_dut_address is not None

            bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
            assert bt_client_address is not None

            found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
            assert found, "device not found"

            with bt_client.interfaces.bluetooth.bt_socket(
                    mode=BTSocketRole.Server
            ) as bt_server_socket:
                # SPP Connection
                with wifi_dut.interfaces.wifi.run_bt_task():
                    bt_server_socket.create_server()
                    connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                    assert connected
                    recv_text = "zvnpoinewnqflkwdnfvoiwnvkwln"
                    time.sleep(2)

                    spp_obj = spp_loopback(bt_server_socket, wifi_dut, recv_text, logger)
                    spp_obj.start()
                ''' Start Iperf traffic DUT as a client and Linux machine as a server '''
                iter_count = utf_constants.get("iter_count")
                for i in range(0, iter_count):
                    filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip,
                                                              suspend_bt_task=0, suspend_ble_task=0)
                time.sleep(2)
                logger().info(f"verifying BT connection after IPERF completion")
                assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
                    dest_addr=bt_dut_address
                )

            bt_server_socket.close()
            wifi_dut.interfaces.wifi.leave()
            time.sleep(2)
            wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as error:
        dut_clean_up(wifi_dut)
        raise


#####################SSL Throughput Test Cases###############################
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
    },
)
def test_ssl_standalone_testcase_tx_C20777(
        wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, utf_constants):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ssl_standalone_testcase_tx_C20777')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    time.sleep(2)
    logger().info("Fetching DUT fw version....")
    wifi_dut.interfaces.wifi.version()
    pkt_count = 30000
    buffer_length = 1370
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)

    iter_count = utf_constants.get("iter_count")
    for count in range(1, iter_count):
        logger().info(f"###############Iteration{count}###############################")
        ssl_server.interfaces.ssl.start_server()
        logger().info(f"###Open ssl client socket in the DUT###")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        logger().info(f"# Enable ssl option for socket opened")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)

        local_port = randint(5001, 60000)
        logger().info(f"*******Socket binds at device_ip with port 5001 in DUT*****")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"****ssl socket opened in DUT connects to the server****")
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

        logger().info(f"****API returns 100 bytes of random data*****")
        data_sent = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
        data_length = len(data_sent)
        logger().info(f"Sending data {data_sent} over socket_no->{sock}")
        logger().info(f" ******DUT sends 100 bytes of data over ssl socket*********")
        wifi_dut.interfaces.wifi.send_data(sock, data_length, data_sent)
        server_socket_no = 1
        logger().info(f"***####SSL server receives the data over ssl socket****####")
        data_receive = ssl_server.interfaces.ssl.data_recv_content(server_socket_no, data_length)
        logger().info(f"Data received on remote socket opened is {data_receive}")
        assert data_sent == data_receive.decode(), "Data sent by DUT and received on server is matching"
        logger().info("Data sent by DUT and received on server is matching")

        if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
            ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
        result = wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
        logger().info(f"Number of bytes sent by dut {result}")
        bytes_sent = result

        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)

        logger().info(
            f"bytes sent by DUT on the ssl socket opened-> {bytes_sent}, received by remote peer-> {bytes_received}")

        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(2)
    logger().info("DUT is going to leave AP")
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ca_cert": "ca-chain.cert.pem",
        "set_send_feature_frame": True,
    }
)
def test_ssl_standalone_testcase_rx_C20778(wifi_sniffer, wifi_access_point, wifi_dut, ssl_server, utf_constants):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ssl_standalone_testcase_rx_C20778')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    time.sleep(2)
    logger().info("Fetching DUT fw version....")
    wifi_dut.interfaces.wifi.version()
    pkt_count = 30000
    buffer_length = 1370
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    bytes_sent = (pkt_count * buffer_length)

    iter_count = utf_constants.get("iter_count")
    for count in range(1, iter_count):
        logger().info(f"###############Iteration{count}###############################")
        ssl_server.interfaces.ssl.start_server()
        wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                               tcp_tx_only_sockets=0,
                                               tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                               tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=44,
                                               tcp_rx_window_div_factor=10)
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                               socket_flag=SocketType.ASYNCHRONOUS)
        assert sock == 0, "Socket id received is wrong. expected is 0"
        logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
        logger().info("Enable ssl option for socket opened")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        local_port = randint(5001, 60000)
        logger().info(f"Socket binds with device_ip and Port number {local_port} in DUT")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        logger().info(f"ssl socket opened in DUT connects to the ssl server")
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        server_socket_no = 1
        pkt_count = 50000
        duration = 60
        ssl_server.interfaces.ssl.send_data(server_socket_no, pkt_count, msg_length=buffer_length, duration=duration)
        time.sleep(80)
        bytes_sent = ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
        result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
        logger().info(f"*** result of rx_stats in wifidut {result}")
        bytes_received = int(result.split(b":")[1])
        logger().info(f"bytes sent by remote peer -> {bytes_sent}")
        logger().info(f"bytes received on socket {sock} -> {bytes_received}")
        logger().info(f"SSL rx throughput ->  {((bytes_received * 8) / (1000 * 1000 * duration))} Mbps")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, "unable to close opened ssl socket in the dut"
        logger().info("Successfully closed opened socket in the DUT")
        ssl_server.interfaces.ssl.stop_server()
        time.sleep(5)

    logger().info("DUT is going to leave the AP")
    wifi_dut.interfaces.wifi.leave()
    time.sleep(1)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")

@pytest.mark.bt_classic
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.TCP_ACK_CORRECT,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
    },
)
def test_ssl_wlan_bt_data_transfer_tcp_tx_C20760(
        wifi_sniffer, bt_client, wifi_access_point, wifi_dut, ssl_server):
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ssl_wlan_bt_data_transfer_testcase_tx_C20760')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    time.sleep(2)
    logger().info("Fetching DUT fw version....")
    wifi_dut.interfaces.wifi.version()
    bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
    assert bt_dut_address is not None

    bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
    assert bt_client_address is not None

    found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
    if not found:
        logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")
    # thread_lock = threading.Lock()
    with bt_client.interfaces.bluetooth.bt_socket(
            mode=BTSocketRole.Server
    ) as bt_server_socket:
        # SPP Connection
        with wifi_dut.interfaces.wifi.run_bt_task():
            bt_server_socket.create_server()
            connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
            assert connected
            recv_text = "9cDKpYOnOJeqYPsL987v"
            time.sleep(1)
            spp_obj = spp_loopback_ssl(bt_server_socket, wifi_dut, recv_text, logger)
            spp_obj.start()
            time.sleep(3)
        pkt_count = 30000
        buffer_length = 1370
        port1 = ssl_server.interfaces.ssl.config['device_port1']
        bytes_sent = (pkt_count * buffer_length)
        iterations = 2
        for count in range(1, iterations):
            logger().info(f"###############Iteration{count}###############################")
            ssl_server.interfaces.ssl.start_server()
            logger().info(f"###Open ssl client socket in the DUT###")
            # thread_lock .acquire()
            sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
            assert sock == 0, "Socket id received is wrong. expected is 0"
            logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            logger().info(f"# Enable ssl option for socket opened")
            wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                       SocketOptions.SSL_ENABLE)
            local_port = randint(5001, 60000)
            logger().info(f"*******Socket binds at device_ip with port 5001 in DUT*****")
            wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
            logger().info(f"****ssl socket opened in DUT connects to the server****")
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
            server_socket_no = 1
            if ssl_server.interfaces.ssl.config['type'] == "ssl.server.ssl_linux":
                ssl_server.interfaces.ssl.data_receive(server_socket_no, pkt_count, buffer_length)
            wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, time_interval=480)
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(server_socket_no)
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, "unable to close opened ssl socket in the dut"
            logger().info("Successfully closed opened socket in the DUT")
            # thread_lock.release()
            time.sleep(2)
            ssl_server.interfaces.ssl.stop_server()

            time.sleep(2)
        time.sleep(3)
        logger().info("DUT is going to leave AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")

@pytest.mark.bt_classic
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.NWP160MHz,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_WINDOW_DIV,
        "set_send_feature_frame": 1,
        "ca_cert": "ca-chain.cert.pem",
    },
)
def test_ssl_wlan_bt_data_transfer_tcp_rx_C20761(
        wifi_sniffer, bt_client, wifi_access_point, wifi_dut, ssl_server):
    with BleLogs(start_collecting_logs=True,
                 bt_log_path=f"reports/test_ssl_standalone_testcase_rx_C20778.log_{int(time.time())}"):
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_ssl_wlan_bt_data_transfer_tcp_rx_C20761')
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
        wifi_dut.interfaces.wifi.start_ip()
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        time.sleep(2)
        logger().info("Fetching DUT fw version....")
        wifi_dut.interfaces.wifi.version()
        bt_dut_address, pin_code = wifi_dut.interfaces.wifi.start_bt_slave_spp()
        assert bt_dut_address is not None

        bt_client_address = bt_client.interfaces.bluetooth.start_spp_master(bt_dut_address, pin_code)
        assert bt_client_address is not None

        found = bt_client.interfaces.bluetooth.bt_adapter.scan_for_device(bt_dut_address, duration=20, retry_counts=3)
        if not found:
            logger().error(f"Dut was not found during the scan by bt client. The test case may fail.")

        with bt_client.interfaces.bluetooth.bt_socket(
                mode=BTSocketRole.Server
        ) as bt_server_socket:
            # SPP Connection
            with wifi_dut.interfaces.wifi.run_bt_task():
                bt_server_socket.create_server()
                connected = bt_server_socket.connect(dest_mac_addr=bt_dut_address, retry_counts=3)
                assert connected
                recv_text = "9cDKpYOnOJeqYPsL987v"
                time.sleep(2)
                spp_obj = spp_loopback_ssl(bt_server_socket, wifi_dut, recv_text, logger)
                spp_obj.start()
            pkt_count = 30000
            buffer_length = 1370
            port1 = ssl_server.interfaces.ssl.config['device_port1']
            bytes_sent = (pkt_count * buffer_length)

            iterations = 2
            for count in range(1, iterations):
                logger().info(f"###############Iteration{count}###############################")
                ssl_server.interfaces.ssl.start_server()
                wifi_dut.interfaces.wifi.socket_config(total_sockets=1, total_tcp_sockets=1, total_udp_sockets=0,
                                                       tcp_tx_only_sockets=0,
                                                       tcp_rx_only_sockets=1, udp_tx_only_sockets=0, udp_rx_only_sockets=0,
                                                       tcp_rx_high_performance_sockets=1, tcp_rx_window_size_cap=44,
                                                       tcp_rx_window_div_factor=10)
                sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                                       socket_flag=SocketType.ASYNCHRONOUS)
                assert sock == 0, "Socket id received is wrong. expected is 0"
                logger().info(f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
                logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
                logger().info(f" *****# Enable ssl option for socket opened *****#")
                wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                           SocketOptions.SSL_ENABLE)

                wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, 38,
                                                           128)

                local_port = randint(5001, 60000)
                logger().info(f"#*****Socket binds with device_ip and Port number 5001 in DUT****#")
                wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
                logger().info(f"#****ssl socket opened in DUT connects to the server****#")
                wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
                server_socket_no = 1
                pkt_count = 50000
                duration = 60
                with TimeMeasurer() as t:
                    ssl_server.interfaces.ssl.send_data_socket(server_socket_no, pkt_count, msg_length=buffer_length,
                                                               duration=duration)
                time_duration = t.duration
                result = wifi_dut.interfaces.wifi.close_socket(sock)
                time.sleep(2)
                assert b"success" in result, "unable to close opened ssl socket in the dut"
                logger().info("Successfully closed opened socket in the DUT")
                bytes_sent = ssl_server.interfaces.ssl.data_send_stats(server_socket_no)
                result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
                bytes_received = int(result.split(b":")[1])
                logger().info(f"bytes sent by remote peer -> {bytes_sent}")
                logger().info(f"bytes received on socket {sock} -> {bytes_received}")
                logger().info(f"SSL rx throughput ->  {(bytes_received * 8) / (1000 * 1000 * time_duration)} Mbps")
                ssl_server.interfaces.ssl.stop_server()
        logger().info("DUT is going to leave the AP")
        wifi_dut.interfaces.wifi.leave()
        time.sleep(1)
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")





