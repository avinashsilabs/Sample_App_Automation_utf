import re
import time
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

)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


def logger():
    return get_logger(__name__)


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

    def start_iperf_dut_as_client(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip):
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
                time=net_perf_client.interfaces.net_perf.client_timeout) as obj:
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

    def start_iperf_dut_as_server(self, wifi_dut, wifi_client, net_perf_client, protocol, device_ip):
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
        bus = ble_client.interfaces.bluetooth.bus
        servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        assert len(servs) > 0
        assert len(chars) > 0

        char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus,
                                                                                               services=servs,
                                                                                               service_uid=service_uid,
                                                                                               char_uid=char_uid)
        assert char is not None
        assert len(char_props) > 0

        # read value - Notifications not enabled
        result = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)
        time.sleep(2)
        # notify only
        wifi_dut.interfaces.wifi.ble_notify_value()

        # subscribe to notifications
        ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_standalone_tcp_rx_c20741(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

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
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_standalone_tcp_tx_c20740(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_standalone_tcp_tx_c20740')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_standalone_udp_rx_c20739(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

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
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_standalone_udp_tx_c20738(wifi_sniffer, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_standalone_udp_tx_c20738')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    wifi_dut.interfaces.wifi.leave()
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
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_bt_connected_tcp_rx_c20751(wifi_sniffer, bt_client, bt_dut, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

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

            # assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            #     dest_addr=bt_dut_address
            # )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
        dest_addr=bt_dut_address
    )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
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
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_bt_connected_tcp_tx_c20750(wifi_sniffer, bt_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

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
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
        dest_addr=bt_dut_address
    )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
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
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_bt_connected_udp_rx_c20749(wifi_sniffer, bt_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

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

            # assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
            #     dest_addr=bt_dut_address
            # )

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    assert bt_client.interfaces.bluetooth.bt_adapter.l2ping(
        dest_addr=bt_dut_address
    )
    bt_server_socket.close()
    wifi_dut.interfaces.wifi.leave()
    time.sleep(2)
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
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_bt_connected_udp_tx_c20748(wifi_sniffer, bt_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

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
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

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
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_ble_connected_tcp_rx_c20747(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

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

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

    logger().info(f"connection existed for {disconnect_time - connect_time}")

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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_ble_connected_tcp_tx_c20746(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

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

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

    logger().info(f"connection existed for {disconnect_time - connect_time}")
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
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_ble_connected_udp_rx_c20745(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

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

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_client(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

    logger().info(f"connection existed for {disconnect_time - connect_time}")

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
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "band": 2
    },
)
def test_wlan_ble_connected_udp_tx_c20744(wifi_sniffer, bt_dut, ble_client, wifi_access_point, wifi_client, wifi_dut, net_perf_client, protocol):
    """ Verify whether DUT is coming out of power save or not if AP is not responding to the PS-POLL for 10msec in
    WLAN+DUAL mode """

    filter_pack_obj = FilterPacket()

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wlan_ble_connected_tcp_rx_c20747')
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger().info("Setting the dut IO capability to display only.....")
    bt_dut.interfaces.bluetooth.bt_set_ssp_mode(pair_mode=1, capability=0)

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

    logger().info("Connect to the dut with mac address..")
    connect_time = datetime.datetime.now(ble_client.interfaces.bluetooth.connect(bt_dut_address))
    logger().info(f"connect_time  {connect_time}")
    assert bt_dut_address, "unable to connect to the given address"
    time.sleep(2)

    ''' Start Iperf traffic DUT as a server and Linux machine as a Client '''
    iter_count = 3
    for i in range(0, iter_count):
        filter_pack_obj.start_iperf_dut_as_server(wifi_dut, wifi_client, net_perf_client, protocol, device_ip)

    state = bt_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    logger().info(f"state_int==============>>,  {state_int}")
    if (state_int > 0):
        logger().info("Disconnecting the bt host....")
        disconnect_time = datetime.datetime.now(
            bt_dut.interfaces.bluetooth.ble_disconnect(ble_remote_dev_address=bt_client_address))
        logger().info(f"disconnect_time  {disconnect_time}")
        assert "unable to disconnect since the connection never existed"

    logger().info(f"connection existed for {disconnect_time - connect_time}")
    logger().info(f"DUT going to leave AP")
    wifi_dut.interfaces.wifi.leave()
    logger().info(f"Sniffer going to stop")
    wifi_sniffer.interfaces.capture.stop_capture()




