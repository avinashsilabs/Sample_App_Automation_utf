import re
import time
from retry import retry
from random import randint
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf.utils.thread_base import ThreadBase
from utf import UtfDatabaseProperties
from test_wlan_data_rates_sdk import SocketDataTransfer
from utf.utils.logger import get_logger
from utf_wiseconnect_3.tests.devices.si91x import (
    Si91xOperatingMode,
    Si91xCoexMode,
    Si91xFeatureBitMap,
    Si91xTCPIPFeatureBitMap,
    Si91xCustomFeatureBitMap,
    Si91xExtCustomFeatureBitMap,
    Si91xBTFeatureBitMap,
    Si91xExtTCPIPFeatureBitMap,
    Si91xBLEFeatureBitMap,
    Si91xBLECustomFeatureBitMap,
    Si91xConfigFeatureBitMap,
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus
from utf.interfaces.iperf.iperf_constants import IperfConstants

"""Author : Vivek"""

"""This function runs below test steps for DUT-Si91x for IoT socket test case verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new IoT TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number and send/receive data.
       
    setup requirement:
        1. DUT(Soc917)
        2. Raspberry PI4
        3. Access Point(Third Party AP's)
        4. Sniffer(NUC device)
"""

def logger():
    return get_logger(__name__)

class IoTSocketDataTransfer:
    def __init__(self, wifi_dut=None, dut_ip=None, time_period=None, data=None, data_transfer=True, switch=None,
                 wifi_access_point=None):
        self.wifi_dut = wifi_dut
        self.dut_ip = dut_ip
        self.time_period = time_period
        self.data = data
        self.data_transfer = data_transfer
        self.switch = switch
        self.socket_id = None
        self.wifi_access_point = wifi_access_point

    def socket_data_transfer(self, stream_type = 'stream', protocol = 'tcp'):
        if isinstance(self.wifi_dut.interfaces.wifi, SLWifiCLI):
            self.socket_id = self.wifi_dut.interfaces.wifi.iotSocketCreate(stream_type=stream_type, protocol=protocol)
            if isinstance(self.socket_id, int):
                logger().info(f"Socket open successfully : {self.socket_id}")
            else:
                logger().error(f"Unable to open socket id: {self.socket_id}")
                raise RuntimeError(self.socket_id)

            logger().error(f"\n\n Socket bind in DUT for socket-id: {self.socket_id}")
            self.wifi_dut.interfaces.wifi.iotSocketBind(socket=self.socket_id, client_ip=self.dut_ip)
            time.sleep(5)
            logger().error(f"\n\n Trying to connect with server ")
            assert self.wifi_dut.interfaces.wifi.iotSocketConnect(socket=self.socket_id, timeout=30)

            if self.data_transfer:
                sw = Stopwatch()
                while sw.elapsed_sec < self.time_period:
                    self.wifi_dut.interfaces.wifi.iotSocketSend(self.socket_id, data=self.data, timeout=120)
            time.sleep(5)
            self.wifi_dut.interfaces.wifi.iotSocketClose(self.socket_id, timeout=30)


class WLanThread(ThreadBase):
    def __init__(self, wifi_dut=None, wifi_access_point=None, wifi_sniffer=None, test_case_no=None, time_period=None
                 , ping_count=None, data_transfer=None, test_name=None, sl_collections=None, data_rates=None,
                 socket_server=None, net_perf_client=None, wifi_client=None):
        super().__init__()
        self.protocol = None
        self.stream_type = None
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.time_period = time_period
        self.data = 'Thisisfromclient'
        self.ping_count = ping_count
        self.dut_addr = None
        self.wifi_sniffer = wifi_sniffer
        self.test_case_no = test_case_no
        self.data_transfer = data_transfer
        self.sl_collections = sl_collections
        self.test_name = test_name
        self.data_rates = data_rates
        self.socket_server = socket_server
        self.net_perf_client = net_perf_client
        self.protocol = None
        self.wifi_client=wifi_client

    def run(self):
        try:
            if self.test_case_no == 19255:
                self.stream_type = 'stream'
                self.protocol = 'tcp'


            if self.test_case_no == 19256:
                self.stream_type = 'dgram'
                self.protocol = 'udp'

            self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.test_name)
            self.dut_addr = self.sl_collections.join_to_wifi_network(wifi_dut=self.wifi_dut,
                                                                     wifi_access_point=self.wifi_access_point,
                                                                     associated=self.wifi_dut.interfaces.wifi.associated
                                                                     , ping_after_power_save=False,
                                                                     channel=self.wifi_access_point.interfaces.wifi.channel)
            logger().info("DUT successfully connected with AP")

            if self.socket_server:
                host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
                logger().info(f"Remote device ip :{host_ip}")
                self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=self.dut_addr['device_ip'],
                protocol=self.protocol.upper())
                self.net_perf_client.interfaces.net_perf.start()

            if self.data_transfer:
                self.iot_socket_obj = IoTSocketDataTransfer(wifi_dut=self.wifi_dut,
                                                            wifi_access_point=self.wifi_access_point,
                                                            time_period=self.time_period, data=self.data,
                                                            dut_ip=self.dut_addr['device_ip'])
                self.iot_socket_obj.socket_data_transfer(stream_type=self.stream_type, protocol=self.protocol)

        except Exception as e:
            logger().info(f"\n\n **** Got exception in test case {self.test_case_no} thread: {str(e)} ****\n\n")
            raise e

class ThreadS(ThreadBase):
    def __init__(self, wifi_dut, socket_id, port_no, connection_type='tcp'):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.sock_id = socket_id
        self.port_no = port_no
        self.connection_type = connection_type

    def run(self):
        if self.connection_type == 'tcp':
            self.wifi_dut.interfaces.wifi.iotSocketAccept(socket=self.sock_id, port=self.port_no)
        else:
            self.wifi_dut.interfaces.wifi.iotSocketReceiveFrom(socket=self.sock_id, port=self.port_no)


class ThreadC(ThreadBase):
    def __init__(self, client_socket, wlan_obj, wifi_dut, socket_id, port_no, host_ip, connection_type='tcp'):
        super().__init__()
        self.client_socket = client_socket
        self.wlan_obj = wlan_obj
        self.wifi_dut = wifi_dut
        self.socket_id = socket_id
        self.port_no = port_no
        self.host_ip = host_ip
        self.connection_type = connection_type

    def run(self):
        tx_buffer = "12345678901234567890123456789012345678901234567890"
        if self.connection_type == 'tcp':
            self.client_socket.connect_client_tcp(self.wlan_obj.dut_addr['device_ip'], self.port_no, self.host_ip)
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                self.client_socket.send_data_tcp(tx_buffer)
                result = self.wifi_dut.interfaces.wifi.iotSocketReceive(socket=self.socket_id)
                logger().info(f"data = {result}")
        else:
            self.client_socket.connect_client_tcp(self.wlan_obj.dut_addr['device_ip'], self.port_no, self.host_ip)
            sw = Stopwatch()
            while sw.elapsed_sec < 10:
                self.client_socket.send_data_udp(tx_buffer, server_ip=self.wlan_obj.dut_addr['device_ip'],
                                                 port=self.port_no)
                result = self.wifi_dut.interfaces.wifi.iotSocketReceive(socket=self.socket_id)
                logger().info(f"data = {result}")


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_iot_socket_tcp_dl(wifi_access_point, wifi_dut, utf_constants,
                                         sl_collections, net_perf_client, wifi_sniffer, wifi_client):
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          time_period=time_period, sl_collections=sl_collections, test_case_no=19255,
                          wifi_sniffer=wifi_sniffer, net_perf_client=net_perf_client,
                          socket_server=True, wifi_client=wifi_client, data_transfer=True)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(5)

        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 1, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_iot_socket_udp_dl(wifi_access_point, wifi_dut, utf_constants,
                                         sl_collections, net_perf_client, wifi_sniffer, wifi_client):
    time_period = utf_constants.get("time_period")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          time_period=time_period, sl_collections=sl_collections, test_case_no=19256,
                          wifi_sniffer=wifi_sniffer, net_perf_client=net_perf_client,
                          socket_server=True, wifi_client=wifi_client, data_transfer=True)
    try:
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        net_perf_client.interfaces.net_perf.close_files()
        net_perf_client.interfaces.net_perf.iperf_process.stop(5)
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 2, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_iot_socket_tcp_ul(wifi_access_point, wifi_dut, utf_constants,
                                         sl_collections, wifi_sniffer, remote_socket_factory, wifi_client):
    time_period = utf_constants.get("time_period")
    local_port = randint(5001, 65535)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          time_period=time_period, sl_collections=sl_collections, test_case_no=19255,
                          wifi_sniffer=wifi_sniffer)
    try:
        '''DUT as SERVER & RESPI as a CLIENT with TCP connection '''
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        socket_id = wifi_dut.interfaces.wifi.iotSocketCreate()
        wifi_dut.interfaces.wifi.iotSocketBind(socket=socket_id, client_ip=wlan_obj.dut_addr['device_ip'], port=local_port)
        wifi_dut.interfaces.wifi.iotSocketListen(socket=socket_id, backlog=1, timeout=20)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()

        with ThreadS(wifi_dut, socket_id, local_port), ThreadC(client_socket, wlan_obj, wifi_dut, socket_id,
                                                               local_port, host_ip):
            time.sleep(20)

        wifi_dut.interfaces.wifi.iotSocketClose(socket_id, timeout=30)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "unassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "thread_config": { "wifi":{ "count": 2, "stack_len": 2048 }} ,
        "oper_mode": Si91xOperatingMode.WiFiClient,
        "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
        "features": Si91xFeatureBitMap.Default,
        "custom_features": Si91xCustomFeatureBitMap.Default,
        "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid |
                              Si91xExtTCPIPFeatureBitMap.WaitForSocketClose,
        "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": 0,
        "ble_features": 0,
        "ble_custom_ext_features": 0,
    },
)
def test_wifi_sdk_iot_socket_udp_ul(wifi_access_point, wifi_dut, utf_constants,
                                         sl_collections, wifi_sniffer, remote_socket_factory, wifi_client):
    time_period = utf_constants.get("time_period")
    local_port = randint(5001, 65535)
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")

    wlan_obj = WLanThread(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point,
                          time_period=time_period, sl_collections=sl_collections, test_case_no=19255,
                          wifi_sniffer=wifi_sniffer)
    try:
        '''DUT as SERVER & RESPI as a CLIENT with UDP connection'''
        wlan_obj.start()
        wlan_obj.wait_for_exit()

        socket_id = wifi_dut.interfaces.wifi.iotSocketCreate(stream_type="dgram", protocol = 'udp')
        wifi_dut.interfaces.wifi.iotSocketBind(socket=socket_id, client_ip=wlan_obj.dut_addr['device_ip'],
                                               port=local_port)
        # wifi_dut.interfaces.wifi.iotSocketListen(socket=socket_id, backlog=1, timeout=20)

        client_socket = remote_socket_factory.interfaces.socket.create_socket()

        with ThreadS(wifi_dut, socket_id, local_port, connection_type='udp'), ThreadC(client_socket, wlan_obj, wifi_dut, socket_id,
                                                               local_port, host_ip, connection_type='udp'):
            time.sleep(20)

        wifi_dut.interfaces.wifi.iotSocketClose(socket_id, timeout=30)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_dut.interfaces.wifi.leave()

    except Exception as e:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=e)

