import time
import pytest
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
    Si91xRegion,
    Si91xRegionCode,
    Si91xModuleType,
    Si91xPowerSaveModes,
    Si91xPowerSaveProcedureTypes,
    Si91xJoinFeatureBitMap,
    Si91xCertificateType,
    Si91xCertIdentifier,
    DefaultCipher,
    Cipher,
)
from utf.utf_config import UtfConfig
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils import get_tls_certificate_dir
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import AsyncEventIdentifiers
import re
from random import randint
from threading import Thread
import threading
import string
import random
ble_obj = None

def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(Si917)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Intel NUC(Wireless Sniffer)

    Test Steps:
        1. Configure the DUT in WLAN+BLE coex mode for 2.4GHz
        2. Join to the access point and get IP through DHCP
        3. Enable the WLAN and BT power save mode in DUT after the connection
        4. Initiate ping from the AP backend machine
        5. BLE advertise and connection
        6. Device is in TA and M4 power save
        7. WLAN connect to SSL/TCP server
        8. BLE enable the notify property
        9. DUT receive the data from Raspi(BLE), transmits to SSL server and vice versa.

    Author: Hari Bhargav Nalla

"""
# this thread used for Wi-Fi join
class WifiThread(ThreadBase):
    """This function is responsible for wifi scan ,connectivity ,powersave ,data transfer"""

    def __init__(
        self,
        wifi_sniffer=None,
        wifi_dut=None,
        wifi_access_point=None,
        testcase=None,
        wifi_client=None,
        net_perf_client=None,
        protocol=None,
        test_type=None,
        sl_collections=None,
        ping_count=None,
        sniffer_filter=None,
        region=None,
        switch=None,
        local_port=None,
        ssl_server=None,
        remote_socket_factory=None
    ):

        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.sl_collections = sl_collections
        self.ping_count = ping_count
        self.sniffer_filter = sniffer_filter
        self.region = region
        self.switch = switch
        self.device_ip = None
        self.dut_mac_address = None
        self.ap_mac_address = None
        self.local_port = local_port
        self.ssl_server = ssl_server
        self.sock_id = None
        self.remote_socket_factory = remote_socket_factory
        self.power_save = UtfConfig.instance().defaults["wifi"].get("power_save", None)
        logger().info(f"in harness power_save flag set to be : {self.power_save}")
        self.client_socket = None
        self.socket_id = None


    def join_to_ap(self):

        if not self.wifi_dut.interfaces.wifi.associated:
            logger().info("Enabling rejoin parameters")
            self.wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(
                max_retry_attempts=0,
                scan_interval=4,
                beacon_missed_count=40,
                first_time_retry_enable=0,
            )
            if self.power_save:
                logger().info(f"Configuring Listen interval based power save")
                self.wifi_dut.interfaces.wifi.set_join_feature_bitmap(join_feature_bitmap=
                                                                  Si91xJoinFeatureBitMap.ListenIntervalFromJoin)
            self.dut_addr = self.sl_collections.join_to_wifi_network(
                wifi_dut=self.wifi_dut,
                wifi_access_point=self.wifi_access_point,
                power_save=self.power_save,
                associated=self.wifi_dut.interfaces.wifi.associated,
                retry_count=3,
                ping_after_power_save=True,
                ping_count=self.ping_count,
            )
            self.device_ip = self.dut_addr["device_ip"]
            self.dut_mac_address = self.dut_addr["dut_mac_address"]
            logger().info(
                f"*****************DUT_MAC_ADDR : {self.dut_mac_address}*********************"
            )
            self.ap_mac_address = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {self.ap_mac_address}")


    def sniffer_validation_join(self):
        self.sl_collections.join_sniffer_validation(
            self.wifi_access_point,
            self.wifi_sniffer,
            self.dut_mac_address,
            self.ap_mac_address,
            self.sniffer_filter,
            power_save=self.power_save,
        )

        if self.power_save:
            packet_filter1 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address, filter_name="ps_poll"
                )
            )
            logger().info(f"Validating PS-POLL frames ")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter1
            )["packet_count"], "Sniffer: Unable to find ps poll packets in sniffer"
            packet_filter2 = (
                self.sniffer_filter.interfaces.ws_sniffer_filter.get_sniffer_filter(
                    sa_addr=self.dut_mac_address,
                    da_addr=self.ap_mac_address,
                    filter_name="qos_data_more_data",
                )
            )
            logger().info(f"Validating QOS data frames with more data bit set")
            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(
                packet_filter1=packet_filter2
            )[
                "packet_count"
            ], "Sniffer: Unable to find QOS data frames with more data bit set in sniffer"

    def set_cert(self, ca_cert=None):

        if ca_cert is not None:
            self.wifi_dut.interfaces.wifi.set_ssl_certificate(str(get_tls_certificate_dir().joinpath(ca_cert)),
                                                              Si91xCertificateType.SL_NET_SIGNING_CERTIFICATE,
                                                              Si91xCertIdentifier.SL_NET_TLS_SERVER_CREDENTIAL_START,
                                                              cert_index=0)

    def disconnect(self):
        if self.wifi_dut.interfaces.wifi.associated:
            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

    def data_from_dut_to_ssl_server(self):
        if self.wifi_dut.interfaces.wifi.associated:
            server_socket_no = 1
            message = 'DatafromSi917wlandev'
            #message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
            logger().info(f"Sending data '{message}' over socket_no->{self.sock_id}")
            self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.sock_id, data=message)
            time.sleep(1)
            data_receive = self.ssl_server.interfaces.ssl.data_recv_content(server_socket_no, buffer_size=len(message))
            logger().info(f"Data received on remote socket opened is {data_receive}")
            assert message == data_receive.decode(), "Data sent by DUT and received on server is not matching"
            logger().info("Data sent by DUT and received on server is matching\n\n")


    def data_from_tcp_server_to_dut(self):
        tx_buffer = "".join(random.choices(string.ascii_uppercase + string.digits, k=50))
        buffer_length = len(tx_buffer)
        sw = Stopwatch()
        logger().info(f"Remote peer sending data over socket {self.socket_id} and data:{tx_buffer}")
        self.client_socket.send_data_tcp(tx_buffer, use_server_socket=False)
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.bsdAsyncEvent(time=10)
        buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=self.socket_id + 1)
        logger().info(f"###################### Buffer Data  {buffer_rx}  ######################")
        logger().info(f"###################### Buffer Data Length  {buffer_length}  ######################")
        assert tx_buffer == buffer_rx, f"buffer length sent by remote peer and received on the socket id " \
                                       f"{self.socket_id} opened in the DUT is not matched"
        logger().info("Data sent by remote peer and received on DUT is matching")



    def data_from_ssl_server_to_dut(self):
        if self.wifi_dut.interfaces.wifi.associated:
            message = 'Datafromopensslservr'
            buffer_length = len(message)
            self.ssl_server.interfaces.ssl.send_data(1, 1, buffer_length, message=message)
            buffer_rx = self.wifi_dut.interfaces.wifi.bsdSocketReceiveFrom(socket_fd=self.sock_id)
            assert message == buffer_rx, f"buffer length sent by remote peer and received on the socket id {self.sock_id} opened in the DUT is not matched "


    def close_ssl_server(self):
            if self.wifi_dut.interfaces.wifi.associated:
                self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.sock_id)
                logger().info("Successfully closed opened socket in the DUT")
                self.ssl_server.interfaces.ssl.stop_server()


    def run(self):

        if self.test_type == "ssl":
            server_port = self.ssl_server.interfaces.ssl.config['device_port1']
            self.ssl_server.interfaces.ssl.start_server()
            server_ip = self.ssl_server.interfaces.ssl.server_ip
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.set_socket_config()

            sock = self.wifi_dut.interfaces.wifi.async_sdk_socket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                                  protocol="IPPROTO_TCP")
            #assert sock == 0, "Socket id received is wrong. expected is 0"
            logger().info(
                f"Successfully opened tcp client socket and socket id received is {sock} which is expected")
            logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_setsockopt API")
            # Enable ssl option for socket opened
            self.wifi_dut.interfaces.wifi.bsdSetSocketOpt(sock, option_name="TCP_ULP")
            time.sleep(2)
            self.wifi_dut.interfaces.wifi.bsdSetSocketOptAsync(sock,
                                                               option_name="SL_SI91X_SO_HIGH_PERFORMANCE_SOCKET",
                                                               cert_index=128)
            local_port = randint(5001, 60000)
            self.wifi_dut.interfaces.wifi.bind(socket_fd=sock, device_ip=self.dut_addr['device_ip'], server_port=local_port,
                                               timeout=15)
            time.sleep(3)
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=sock, server_ip=server_ip,
                                                           server_port=server_port)
            self.sock_id = sock

        if self.test_type == "tcp":
            self.client_socket = self.remote_socket_factory.interfaces.socket.create_socket()
            self.socket_id = self.wifi_dut.interfaces.wifi.Asyncsocket(domain="AF_INET", stream_type="SOCK_STREAM",
                                                             protocol="IPPROTO_TCP")
            logger().info(f"Socket open successfully : { self.socket_id}")
            logger().info(
                f"Successfully opened tcp client socket and socket id received is { self.socket_id} which is expected")

            local_port = randint(5001, 60000)
            self.wifi_dut.interfaces.wifi.bind(socket_fd= self.socket_id, device_ip=self.dut_addr['device_ip'],
                                          server_port=local_port, timeout=5, asynch=1)

            self.wifi_dut.interfaces.wifi.listen(socket_fd= self.socket_id, backlog=1, asynch=1)

            ThreadBase.call_functions_simultaneously(
                [
                    (self.wifi_dut.interfaces.wifi.bsdSocketAccept,  self.socket_id, 1),
                    (self.client_socket.connect_client_tcp, self.dut_addr['device_ip'], local_port),
                ],
                timeout=10,
            )

class DataTransfer:
    def __init__(self):
        self.thread_lock = threading.Lock()
        self.sent_data = 0
        self.rcv_data = 0

    def send_and_receive_data_socket(
            self, thread_no, remote_socket, no_of_pkts, data_size, time_interval, wifi_dut, server_sock, local_port, server_ip,
            proto_type=0):

        bytes_sent = wifi_dut.interfaces.wifi.send_data_pkts(
            socket_id=server_sock, pkt_length=data_size, no_of_pkts=no_of_pkts, time_interval=time_interval,
            server_ip=server_ip, server_port=local_port)

        logger().info(f"\n **** Sending {bytes_sent} on Thread {thread_no} \n")
        timeout = 2
        if proto_type == 0:
            remote_socket.set_recv_timeout(socket_type=0, timeout=timeout)
        else:
            remote_socket.set_recv_timeout(socket_type=1, use_client_socket=True, timeout=timeout)
        for i in range(0, no_of_pkts):
            if proto_type == 0:
                data = remote_socket.recv_data_tcp(data_size, timeout=timeout)
                logger().info(f' ---- TCP RX on Thread {thread_no} is : {data} ---- ')
            else:
                data, address = remote_socket.recv_data_udp(data_size, timeout=timeout)
                logger().info(f' ---- UDP RX on Thread {thread_no} is : {data} ---- ')
            if not isinstance(data, str):
                logger().info(f"\n **** Unable to Receive on Socket: {server_sock} **** \n")
                break
            self.rcv_data = self.rcv_data + len(data)
            if self.rcv_data == len(bytes_sent):
                break

        remote_socket.socket_close_indication(1)
        logger().info(f"Total bytes received on Socket {server_sock} and Thread {thread_no} opened remotely is -> {self.rcv_data}")
        if proto_type == 0:
            assert self.rcv_data == int(
                bytes_sent), f"Data transfer failed. Expected {bytes_sent} bytes but received {self.rcv_data} bytes"
        else:
            logger().info(f"Data transfer Successful. Sent {bytes_sent} bytes and received {self.rcv_data} bytes on thread : {thread_no}, "
                          f"the observed UDP packet loss is {100 - (int(self.rcv_data) * 100 / int(bytes_sent))}%")

# this thread used for BLE functionality
class BleThread(ThreadBase):
    def __init__(
        self,
        wifi_dut=None,
        ble_client=None,
        ble_test_type=None,
        adv_int=None,
        ble_scan_interval=None,
        ble_scan_window=None,
        sl_collections=None,
        ble_pairing=None,
        min_conn_int=None,
        max_conn_int=None,
        conn_latency=None,
        supervision_timeout=None,
        set_smp = None

    ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = adv_int
        self.ble_dut_address = None
        self.ble_test_type = ble_test_type
        self.ble_scan_interval = ble_scan_interval
        self.ble_scan_window = ble_scan_window
        self.sl_collections = sl_collections
        self.ble_pairing = ble_pairing
        self.min_conn_int = min_conn_int
        self.max_conn_int = max_conn_int
        self.conn_latency = conn_latency
        self.supervision_timeout = supervision_timeout
        self.ble_client_address = None
        self.handle = None
        self.char_path = None
        self.char_props = None
        self.set_smp = set_smp

        # Set up DUT for BLE advertising
        logger().info("Initializing BLE")
        #self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start(set_smp=self.ble_pairing)
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start(set_smp=self.set_smp)
        assert (
            self.ble_dut_address is not None
        ), "Unable to fetch bluetooth address from DUT"
        logger().info(f"ble_dut_address : {self.ble_dut_address}")
        time.sleep(5)

    def ble_disconnect(self, disconnect_from="remote"):

        self.sl_collections.ble_disconnect(
            wifi_dut=self.wifi_dut,
            ble_client=self.ble_client,
            ble_dut_address=self.ble_dut_address,
            disconnect_from=disconnect_from,
            ble_client_address=self.ble_client_address,
        )

    def data_from_dut_to_remote_ble(self):
        data = "DatafromSi917device1"
        self.wifi_dut.interfaces.wifi.ble_set_local_att_value(notify_data=data,val_handle=self.handle)
        time.sleep(0.2)
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[self.char_uid]
        assert len(notifications) > 0, "received data is empty"
        logger().info(f"notifications received on remote :{notifications}")
        logger().info(f"length of notifications received on remote :{len(notifications)}")
        assert data in notifications, "failed to fetch data"

    def data_from_remote_ble_to_dut(self):
        data = "DatafromRaspi"
        since_time = time.perf_counter_ns()
        self.ble_client.interfaces.bluetooth.send_gatt_charc_notification(self.service_uid, self.char_uid, data)
        time.sleep(0.3)
        found = False
        tw = Stopwatch()
        while tw.elapsed_sec < 10:
            events = self.ble_dut.interfaces.wifi.get_async_events(since_time=since_time)
            for event in events:
                if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                    logger().info(f"************** BLE EVENT DATA IS : {event.event_data} **************")
                    received_data = re.findall(r"att_value:\s*([^\s]+)", event.event_data)
                    logger().info(f"******* Received Data on DUT : {received_data} ********")
                    assert received_data[0] == data, "data mismatched"
                    if data in event.event_data:
                        found = True
                        break
            assert found, "No data received on DUT"
            if found:
                break

    def run(self):

        if self.ble_test_type == "slave":
            notify_time = 120
            # add BLE service and characteristics into DUT
            self.service_uid = "0000aabb-0000-1000-8000-00805f9b34fb"
            self.char_uid = "00001aa1-0000-1000-8000-00805f9b34fb"
            self.wifi_dut.interfaces.wifi.ble_add_service(uid=0xaabb)
            self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x1aa1)
            self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x1aa1)

            # start BLE advertising
            self.ble_client_address = self.sl_collections.check_ble_advertise_functionality(wifi_dut=self.wifi_dut, ble_client=self.ble_client,
                                                                        ble_dut_address=self.ble_dut_address, timeout=20)

            # Initiate BLE connection and update with 45ms interval
            self.ble_client_address = self.sl_collections.connect_ble(
                wifi_dut=self.wifi_dut,
                ble_client=self.ble_client,
                ble_dut_address=self.ble_dut_address,
                mode=self.ble_test_type,
                retries=3,
                ble_pairing=self.ble_pairing,
                min_conn_interval=self.min_conn_int,
                max_conn_interval=self.max_conn_int,
                conn_latency=self.conn_latency, supervision_timeout=int(self.supervision_timeout)/10
            )

            # Service discovery of DUT from Raspberry Pi
            servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
            assert len(servs) > 0, "no services fetched"
            assert len(chars) > 0, "fetched characters are empty"

            # Get characteristics of DUT from Raspberry Pi
            self.char_path, self.char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(
                services=servs, service_uid=self.service_uid, char_uid=self.char_uid)
            assert self.char_path, "characters are empty"
            assert len(self.char_props) > 0, "length of characters is 0"

            # Read characteristic values
            self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=self.char_path)

            # Enable notifications from Raspberry Pi
            self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(char_path=self.char_path)
            self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(
                        char_path=self.char_path, char_uid=self.char_uid)

            sw = Stopwatch()
            handle_found = False
            while sw.elapsed_sec < notify_time and not handle_found:
                events = self.wifi_dut.interfaces.wifi.get_async_events()
                for event in events:
                    if event.event_type == AsyncEventIdentifiers.GATT_WRITE_EVENT:
                        if "rsi_ble_att_val_hndl_gatt" in event.event_data:
                            received_data = re.findall(r"rsi_ble_att_val_hndl_gatt\s*=\s*(\d+)", event.event_data)
                            self.handle = int(received_data[0].strip())
                            if self.handle:
                                logger().info(f"Handle:{self.handle}")
                                handle_found = True
                                break
                            else:
                                logger().info("Handle not found")
                                assert self.handle

pytestmark = [
    pytest.mark.config(
        "wifi_dut",
        wifi={
            "oper_mode": 0,
            "coex_mode": Si91xCoexMode.WLAN | Si91xCoexMode.BLE,
            "features": Si91xFeatureBitMap.WPSSupportDisabled | Si91xFeatureBitMap.ULPGPIOHandshake | Si91xFeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
            "tcpip_features": Si91xTCPIPFeatureBitMap.DHCPv4Client | Si91xTCPIPFeatureBitMap.SSL | Si91xTCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
            "custom_features": Si91xCustomFeatureBitMap.ExtCustomFeatureBitmapValid,
            "ext_custom_features": Si91xExtCustomFeatureBitMap.Default | Si91xExtCustomFeatureBitMap.BTFeatureBitmapValid | Si91xExtCustomFeatureBitMap.Feature256kBMemoryMode,
            "bt_features": Si91xBTFeatureBitMap.Default,
            "ext_tcpip_features": Si91xExtTCPIPFeatureBitMap.EXT_TCP_IP_TOTAL_SELECTS(10) | Si91xExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
            "ble_features": Si91xBLEFeatureBitMap.Default,
            "ble_custom_ext_features": Si91xBLECustomFeatureBitMap.Default,
            "config_features": Si91xConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | Si91xConfigFeatureBitMap.EnahanceMaxPsp,
            "thread_config": {
            "wifi": {"count": 1, "stack_len": 2048, "priority": 8},
            "ble": {"count": 1, "stack_len": 2048, "priority": 8},
            },
        },
    )
]

@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("ca_cert", ["ca-chain.cert.pem"])

def test_wifi_sdk_wifi_tx_ble_tx_alarm_based_C148629(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    ca_cert,
    ssl_server,
):
    wifi_obj = None
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ssl"
        min_connection_interval = 45
        max_connection_interval = 45
        connection_latency = 0
        supervision_timeout = 32000
        local_port = 5001

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            local_port=local_port,
            ssl_server=ssl_server,
        )

        # BLE Thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            min_conn_int=min_connection_interval,
            max_conn_int=max_connection_interval,
            conn_latency=connection_latency,
            supervision_timeout=supervision_timeout,
            ble_pairing=1,
            set_smp=0
        )

        wifi_obj.set_cert(ca_cert=ca_cert)
        logger().info(f"M4-TA secure handshake")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        # Associate to Access point
        wifi_obj.join_to_ap()
        # Start BLE advertise followed by Raspberry Pi connection with DUT
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()

        logger().info("Checking connection status of BLE")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == 8, f"Device is not in connected state. Expected: 8, Actual: {state_int}"
        logger().info("BLE Device is in connected state")

        logger().info(f"Enabling M4 power save")
        for i in range(0,10):
            wifi_dut.interfaces.wifi.m4_power_manager(sleep_time=3000)
            # Begin data tx from DUT to remote devices
            wifi_obj.data_from_dut_to_ssl_server()
            ble_obj.data_from_dut_to_remote_ble()

        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()
        # Initiate WiFi disconnection
        wifi_obj.disconnect()


    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service()
        wifi_obj.close_ssl_server()
        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()
        # Clean up the BLE based on the device state
        if ble_obj:
            #Remove BLE pair info
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.skip("Not yet deployed due to WIFI_BT_UTFHELP-5628")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

def test_wifi_sdk_wifi_tcp_rx_ble_rx_wireless_based_C148631(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    remote_socket_factory
):
    wifi_obj = None
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "tcp"
        min_connection_interval = 45
        max_connection_interval = 45
        connection_latency = 0
        supervision_timeout = 32000
        local_port = 5001
        smp_enable = 1

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            local_port=local_port,
            remote_socket_factory=remote_socket_factory
        )

        # BLE Thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            min_conn_int=min_connection_interval,
            max_conn_int=max_connection_interval,
            conn_latency=connection_latency,
            supervision_timeout=supervision_timeout,
            ble_pairing=smp_enable,
        )

        # Start BLE advertise followed by Raspberry Pi connection with DUT
        logger().info(f"M4-TA secure handshake")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        # Associate to Access point
        wifi_obj.join_to_ap()
        # Start BLE advertise followed by Raspberry Pi connection with DUT
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        for i in range(0,10):
            # Begin data tx from DUT to remote devices
            wifi_obj.data_from_tcp_server_to_dut()
            ble_obj.data_from_remote_ble_to_dut()
            time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service()
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()

        # Initiate WiFi disconnection
        wifi_obj.disconnect()

        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()

        # Clean up the BLE based on the device state
        if ble_obj:
            # Remove BLE pair info
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)

@pytest.mark.skip("Not yet deployed due to WIFI_BT_UTFHELP-5628")
@pytest.mark.config(
    "wifi_access_point", wifi={"security": "WPA2", "passphrase": "1234567890","dtim": 1}
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=["init"])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("ca_cert", ["ca-chain.cert.pem"])
def test_wifi_sdk_wifi_ssl_rx_ble_rx_C133486(
    wifi_sniffer,
    wifi_access_point,
    wifi_dut,
    ble_client,
    request,
    utf_constants,
    sl_collections,
    wifi_client,
    sniffer_filter,
    ssl_server,
    ca_cert,

):
    wifi_obj = None
    ble_obj = None
    try:
        test_name = request.node.name
        ping_count = utf_constants.get("ping_count")
        test_type = "ssl"
        min_connection_interval = 45
        max_connection_interval = 45
        connection_latency = 0
        supervision_timeout = 32000
        local_port = 5001
        smp_enable = 1

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel
        )
        logger().info(
            "start capturing with Sniffer by giving the test case name as filename"
        )
        # Start Sniffer capture
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # WiFi Thread
        wifi_obj = WifiThread(
            wifi_sniffer=wifi_sniffer,
            wifi_dut=wifi_dut,
            wifi_access_point=wifi_access_point,
            testcase=test_name,
            wifi_client=wifi_client,
            sl_collections=sl_collections,
            ping_count=ping_count,
            sniffer_filter=sniffer_filter,
            test_type=test_type,
            local_port=local_port,
            ssl_server=ssl_server,
        )

        # BLE Thread
        ble_obj = BleThread(
            wifi_dut=wifi_dut,
            ble_client=ble_client,
            sl_collections=sl_collections,
            ble_test_type="slave",
            min_conn_int=min_connection_interval,
            max_conn_int=max_connection_interval,
            conn_latency=connection_latency,
            supervision_timeout=supervision_timeout,
            ble_pairing=smp_enable,
        )

        wifi_obj.set_cert(ca_cert=ca_cert)
        logger().info(f"M4-TA secure handshake")
        wifi_dut.interfaces.wifi.m4_ta_secure_handshake(sub_cmd_type=5, xtal_enable=1)
        # Associate to Access point
        wifi_obj.join_to_ap()
        # Start BLE advertise followed by Raspberry Pi connection with DUT
        ble_obj.start()
        ble_obj.wait_for_exit()
        wifi_obj.start()
        wifi_obj.wait_for_exit()
        logger().info(f"Enabling M4 power save")
        for i in range(0,10):
            # Begin data tx from DUT to remote devices
            wifi_obj.data_from_ssl_server_to_dut()
            ble_obj.data_from_remote_ble_to_dut()
            time.sleep(2)

    except Exception as Ex:
        sl_collections.exception_handling(wifi_dut=wifi_dut, exception=Ex)
    finally:
        logger().info("Finally")
        logger().info("******************** ble_remove_service ***********************")
        wifi_dut.interfaces.wifi.ble_remove_service()
        wifi_obj.close_ssl_server()
        # Stop wireshark sniffer capture
        wifi_sniffer.interfaces.capture.stop_capture()
        # Close the BLE of Raspberry Pi
        ble_client.interfaces.bluetooth.close()
        # Clean up the BLE based on the device state
        if ble_obj:
            # Remove BLE pair info
            ble_client.interfaces.bluetooth.remove_device(ble_obj.ble_dut_address)
            sl_collections.cleanup_ble(ble_dut=wifi_dut, ble_client=ble_client,
                                       ble_client_address=ble_obj.ble_client_address,
                                       ble_dut_address=ble_obj.ble_dut_address)