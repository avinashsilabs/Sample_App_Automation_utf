import datetime
import itertools
import random
import re
import string
import threading
import time
import uuid
from datetime import datetime
from random import randint
import pytest
from retry import retry
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116TCPIPFeatureBitMap, RS9116ExtTCPIPFeatureBitMap,
                                            RS9116CertificateType, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap,
                                            RS9116ExtCustomFeatureBitMap, RS9116PowerSaveModes, SocketOptions, Cipher,
                                            SocketType, RS9116AsyncEventType, RS9116StoreConfiguration, RS9116MqttQos,
                                            RS9116CustomFeatureBitMap, DeviceConstants, RS9116OperatingMode, RS9116Band,
                                            RS9116PowerSaveProcedureTypes, RS9116BTFeatureBitMap)
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.utils.time_measurer import TimeMeasurer
from threading import Thread, Lock
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import print_dict

lock = threading.RLock()


def logger():
    return get_logger(__name__)


"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Test Steps:
        1. Configure the DUT in Wlan coex mode
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify power management bit to be enable in Null data frames 
        5. Initiate BLE advertise/scan

    Author: Swathi , reworked by CG team
"""


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def num_sort(input_string: str):
    return list(map(int, re.findall(r'\d+', input_string)))[0]


def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True, secure_connect=False,
                     skip_scan=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT"):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        if start_needed:
            logger().info(f"Set up DUT for BLE master role")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            logger().info("Started BLE in DUT")
            assert ble_dut_address, f"Unable to fetch ble dut address"
        for retry_count in range(5):
            try:
                logger().info("Start ble client")
                ble_client.interfaces.bluetooth.close()
                time.sleep(3)
                ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
                assert ble_client_address, "Unable to get ble_client_address"
                time.sleep(5)
                if not skip_scan:
                    logger().info("Start scanning and connect to ble client")
                    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
                    time.sleep(2)
                    wifi_dut.interfaces.wifi.ble_stop_scanning()
                time.sleep(5)
                logger().info("Initiating BLE connection with ble_client")
                wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected,
                                                     timeout=120)
                logger().info("BLE Connection success")
                break
            except Exception as e:
                try:
                    logger().info(
                        "*************** Exception block for stop advertising and stop scanning ***************")
                    ble_client.interfaces.bluetooth.stop_advertising()
                    wifi_dut.interfaces.wifi.ble_stop_scanning()
                except:
                    pass
                logger().info(f"Ble Connection Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)

    if mode == "ble_slave":
        try:
            if start_needed:
                logger().info(f"Set up DUT for BLE advertising")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert ble_dut_address, f"Unable to find ble dut address, failed to initiate ble in dut"
            wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            ble_client.interfaces.bluetooth.close()
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"failed to initiate ble in remote device"

            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_scanning()
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"ble_scan_list:\n{found_devices}")
            assert wifi_dut.interfaces.wifi.ble_address in found_devices, "Unable to find our DUT"
            assert (found_devices[
                        wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
            logger().info(f"See that we found our device:'{ble_dut_address}'")
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            ble_client.interfaces.bluetooth.stop_scanning()
            raise e
        logger().info("Initiating BLE Connection from ble_client")
        if secure_connect:
            connect_state = ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=ble_dut_address, timeout=500)
            assert connect_state, "Unable to connect to DUT BLE from raspi"
        else:
            conn_params = {"min_conn_interval": 40,
                           "max_conn_interval": 40,
                           "conn_latency": 0,
                           "supervision_timeout": 200}

            ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
        time.sleep(2)
        logger().info("BLE slave connection success")
    return ble_client_address, ble_dut_address


def check_connection_status(wifi_dut, ble=False, wlan=False):
    if ble:
        logger().info("Checking connection status of BLE")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

    if wlan:
        logger().info("Checking connection status of Wi-Fi")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, f"DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0
        logger().info(f"DUT is not disconnected from Wi-Fi during traffic run for long duration")


def socket_connect(wifi_dut, remote_socket, socket_id, dut_ip, server_port, local_port):
    logger().info("Binding socket in DUT")
    bind_response = wifi_dut.interfaces.wifi.bind(socket_id, dut_ip, local_port)
    logger().info(f"Bind socket successfully: {bind_response}")

    logger().info("DUT is connecting to server socket")
    connect_status = False
    for count in range(3):
        try:
            wifi_dut.interfaces.wifi.connect_to_server(socket_id, remote_socket.interfaces.socket, server_port)
            connect_status = True
            break
        except:
            logger().info(f"Socket connection failed in DUT...retry_count:{count + 1}")
            time.sleep(10)
    assert connect_status, "Socket connection failed in DUT"
    logger().info("Socket connection is successful")
    time.sleep(3)


@retry(Exception, delay=15, tries=3)
def run_tcp_traffic(wifi_dut, remote_socket, dut_ip, data_len=1461):
    logger().info("Starting TCP server socket remotely")
    tcp_port = randint(6000, 6100)
    remote_socket.interfaces.socket.time_limit = 3000
    logger().info("Starting TCP Server socket at remote device")
    remote_socket.interfaces.socket.start_server(socket_type=0, port=tcp_port)  # 0-TCP, 1-UDP
    server_port = remote_socket.interfaces.socket.server_port

    logger().info("Opening TCP client socket in DUT")
    tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
    logger().info(f"Socket open successfully : {tcp_socket_id}")
    time.sleep(5)

    logger().info("Initiating TCP socket connection from DUT")
    socket_connect(wifi_dut, remote_socket, tcp_socket_id, dut_ip, server_port, tcp_port)

    for data_length in range(1, data_len):  # 1461
        data = text_generator(data_length)
        send_data_length = len(data)

        logger().info(f"\n\nInitiating TCP data transfer from DUT with data length:'{send_data_length}'")
        wifi_dut.interfaces.wifi.send(tcp_socket_id, send_data_length)

        logger().info("Validating received data on remote server")
        data_received = remote_socket.interfaces.socket.recv_data_tcp(send_data_length)
        logger().info(f"Length of data received is: '{len(data_received)}'")

        assert send_data_length == len(
            data_received), "data length sent by DUT and received on remote peer is not matching"
        logger().info("data sent by DUT and received on remote peer is matching")
    return tcp_port


@retry(Exception, delay=15, tries=3)
def run_udp_traffic(wifi_dut, remote_socket, dut_ip):
    logger().info("Starting UDP server socket at remote device")
    udp_port = randint(5001, 6000)
    remote_socket.interfaces.socket.time_limit = 3000
    remote_socket.interfaces.socket.start_server(socket_type=1, port=udp_port)  # 0-TCP, 1-UDP
    server_port = remote_socket.interfaces.socket.server_port
    server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()

    logger().info("Opening UDP client socket in DUT")
    udp_socket_id = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
    logger().info(f"Successfully opened UDP client socket on DUT with socket id:'{udp_socket_id}'")

    logger().info("Initiating UDP socket connection from DUT")
    socket_connect(wifi_dut, remote_socket, udp_socket_id, dut_ip, server_port, udp_port)

    for data_length in range(1, 1471):  # 1471
        data = text_generator(data_length)
        send_data_length = len(data)

        logger().info(f"\n\nInitiating UDP data transfer from DUT with data length:'{send_data_length}'")
        wifi_dut.interfaces.wifi.send_to(udp_socket_id, send_data_length, server_ip, server_port)

        logger().info("Validating received data on remote server")
        data_received, _ = remote_socket.interfaces.socket.recv_data_udp(send_data_length)
        logger().info(f"Length of data received is: '{len(data_received)}'")

        assert send_data_length == len(
            data_received), "data length sent by DUT and received on remote peer is not matching"
        logger().info("data sent by DUT and received on remote peer is matching")
    return udp_port


def tcp_udp_packet_check(wifi_sniffer, decryption_key: str, dut_mac_address, tcp_port, udp_port, capture_filename):
    time_stamp = str(datetime.fromtimestamp(time.time()).strftime('%H_%M_%S'))
    updated_capture_file = 'filter_' + capture_filename + '_' + time_stamp
    local_capture_file = f'./reports/{updated_capture_file}.pcap'
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter = f"'(wlan.addr == {dut_mac_address})' -T fields -e frame.number -w {wlan_filter_file}"
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y {packet_filter}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)

    pack_tcp_port, pack_udp_port, tcp_data_list, udp_data_list = [[] for _ in range(4)]
    logger().info("******** Initiating sniffer packets decryption process ---> this will take some time *********")
    for packet in wifi_sniffer.interfaces.capture.iter_packets(decrypt_packets=True, encryption_type="WPA-PWD",
                                                               decryption_key=decryption_key):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "tcp":
                tcp_layer = str(layer)
                # logger().info(tcp_layer)
                tcp_data_list.append(re.findall(f"TCP payload.*", tcp_layer))
                pack_tcp_port.append(re.findall(f"Destination Port:.*{tcp_port}", tcp_layer))
            if layer_name == "udp":
                udp_layer = str(layer)
                # logger().info(udp_layer)
                pack_udp_port.append(re.findall(f"Destination Port:.*{udp_port}", udp_layer))
                if pack_udp_port[-1] and (pack_udp_port[-1][0].split()[-1] == str(udp_port)):
                    udp_data_list.append(re.findall(f"Length:.*", udp_layer))
    tcp_data = list(set(itertools.chain(*(filter(None, tcp_data_list)))))
    udp_data = list(set(itertools.chain(*(filter(None, udp_data_list)))))
    tcp_data.sort(key=num_sort), udp_data.sort(key=num_sort)
    return pack_tcp_port, pack_udp_port, tcp_data, udp_data


def verify_sniffer_valiadation(wifi_sniffer, dut_mac_address, ap_bssid):
    validation = True
    # Validate broadcast probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    logger().info("Validating broadcast probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find broadcast probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'


def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()


def dut_clean_up(wifi_dut, ble_client_address=None):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT -------------------------------")
    try:
        if ble_client_address:
            logger().info("BLE disconnect from DUT")
            try:
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
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed -------------------")


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


def print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)


class ble_master_slave_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode, skip_scan=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT"):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode
        self.expected = expected
        self.skip_scan = skip_scan

    def run(self):
        with lock:
            ble_client_address, ble_dut_address = ble_master_slave(self.wifi_dut, self.ble_client, self.mode,
                                                                   expected=self.expected, skip_scan=self.skip_scan)
        return ble_client_address, ble_dut_address


# this thread is used for AP power ON/OFF
class ap_turn_off_on_thread(ThreadBase):
    def __init__(self, wifi_access_point, wifi_dut, rs_helper, device_ip, wifi_sniffer, dut_mac_address, switch=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.rs_helper = rs_helper
        self.switch = switch
        self.device_ip = device_ip
        self.wifi_sniffer = wifi_sniffer
        self.dut_mac_address = dut_mac_address

    def run(self):
        if self.switch:
            logger().info("Turning off the AP")
            self.switch.interfaces.pdu_switch.turn_off()
            logger().info("Successfully powered off AP")
            time.sleep(30)
            logger().info("Again turning on the AP")
            self.switch.interfaces.pdu_switch.turn_on()
            logger().info("Successfully powered on AP")
            time.sleep(60)
        else:
            logger().info(f"Disabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.stop_ap()
            logger().info("Successfully powered off AP")
            time.sleep(30)
            logger().info(f"Enabling Wireless in AP")
            self.wifi_access_point.interfaces.wifi.start_ap()
            time.sleep(60)

        logger().info("Pinging to DUT to check rejoin process is completed or not")
        status = self.rs_helper.ping_with_custom_size(device_ip=self.device_ip, ping_counts=15)
        assert status, "Pinging to DUT is failed, DUT not rejoined to AP"
        logger().info("************* DUT successfully rejoined to AP *************\n\n")


pytestmark = [pytest.mark.ble_client("raspi_ble_client"), pytest.mark.config('wifi_access_point', wifi={'channel': 3}),
              pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"])]


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "cipher": "AES"})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.remote_socket("raspi_ip_socket")
# In raspi_ip_socket section of harness file interface needs to updated according to the raspi interface which is connected to AP.
def test_verify_tcp_udp_tx_data_transfer_c20224(recovery, remote_socket, rs_helper, utf_constants, wifi_sniffer,
                                                wifi_dut, wifi_access_point, wifi_client, net_perf_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    ble_client_address = None
    try:
        logger().info(
            "testcase : Verify WLAN TCP, UDP Tx data transfer with variable size(1-1460 bytes) after BLE connection")
        logger().info("configuring the Sniffer with the channel")
        testcase = 'verify_tcp_udp_tx_data_transfer_c20224'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        ble_mode = "ble_slave"
        logger().info(f"********* Initiating BLE test with DUT mode '{ble_mode}' *********")
        ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
        logger().info(f"ble_client_address: {ble_client_address}, ble_dut_address: '{ble_dut_address}'")
        time.sleep(3)

        logger().info("Initiating wlan scan from DUT")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        dut_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {dut_ip}, {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_BSSID:'{ap_bssid}'")

        logger().info("Getting the DUT mac")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip :{host_ip}")

        logger().info("\n\n*************** Initiating TCP data transfer from DUT to remote server ***************\n")
        tcp_port = run_tcp_traffic(wifi_dut, remote_socket, dut_ip)
        logger().info("******************************* TCP data transfer completed ******************************")
        time.sleep(5)
        logger().info("\n\n*************** Initiating UDP data transfer from DUT to remote server ***************\n")
        udp_port = run_udp_traffic(wifi_dut, remote_socket, dut_ip)
        logger().info("******************************* UDP data transfer completed ******************************")

        time_duration = utf_constants.get("time_duration")
        time_minutes = round((time_duration / 60), 2)
        logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
        time.sleep(time_duration)
        check_connection_status(wifi_dut, ble=True, wlan=True)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n********************* Validating TCP, UDP packets in sniffer capture **********************")
        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        pack_tcp_port, pack_udp_port, tcp_data_list, udp_data_list = tcp_udp_packet_check(wifi_sniffer, decryption_key,
                                                                                          dut_mac_address, tcp_port,
                                                                                          udp_port,
                                                                                          capture_filename="test_tcp_udp_c20224")
        if pack_tcp_port:
            assert str(tcp_port) in str(pack_tcp_port), f"Unable to find given tcp port {tcp_port} in sniffer packet"
            logger().info(f"\n\n********** Found destination tcp port: '{tcp_port}' in sniffer packets ***********\n")
            logger().info(f"\n********************** Found TCP Data lengths *********************\n{tcp_data_list}\n")
        else:
            logger().info(f"\n*********************** Unable to find TCP packets in sniffer ************************\n")

        if pack_udp_port:
            assert str(udp_port) in str(pack_udp_port), f"Unable to find given udp port {udp_port} in sniffer packet"
            logger().info(f"\n\n********** Found destination udp port: '{udp_port}' in sniffer packets ***********\n")
            logger().info(f"\n********************* Found UDP Data lengths **********************\n{udp_data_list}\n")
        else:
            logger().info(f"\n*********************** Unable to find UDP packets in sniffer ************************\n")

        logger().info("Validating sniffer packets")
        verify_sniffer_valiadation(wifi_sniffer, dut_mac_address, ap_bssid)

    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address)


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "cipher": "AES"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_verify_wlan_scan_and_ble_scan_c20199(wifi_access_point, recovery, wifi_dut, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    try:
        logger().info(
            "testcase : Verify WLAN scan and BLE scan")

        logger().info(f"Set up DUT for BLE master role")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("Started BLE in DUT")
        assert ble_dut_address, f"Unable to fetch ble dut address"
        try:
            logger().info("Start ble client for advertising")
            ble_client.interfaces.bluetooth.close()
            time.sleep(3)
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, "Unable to get ble_client_address"
            time.sleep(5)
            logger().info("Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            time.sleep(5)
            logger().info("BLE scanning successful from DUT")
            wifi_dut.interfaces.wifi.ble_stop_scanning()
        except Exception as err:
            logger().info(
                "*************** Exception block for stop advertising and stop scanning ***************")
            ble_client.interfaces.bluetooth.stop_advertising()
            wifi_dut.interfaces.wifi.ble_stop_scanning()
            raise err
        time.sleep(3)
        logger().info("\n\n************************* Initiating wlan_scan from DUT ****************************")
        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(f"\n***************** wlan_scan successful in {t.duration} seconds *****************\n")
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)


@pytest.mark.skip()
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "cipher": "AES"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.remote_socket("raspi_ip_socket")
# In raspi_ip_socket section of harness file interface needs to updated according to the raspi interface which is connected to AP.
def test_tcp_data_transfer_functionality_while_rejoin_c20225(switch, utf_constants, rs_helper, wifi_sniffer, recovery,
                                                             wifi_dut, wifi_access_point, ble_client, remote_socket):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    ble_client_address = None
    try:
        testcase = "test_TCP_functionality_while_rejoin_C20225"
        logger().info("testcase : TCP data transfer functionality while STA is in rejoin process")

        logger().info("Setting Rejoin Parameters in DUT")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        ble_mode = "ble_slave"
        logger().info(f"********* Initiating BLE test with DUT mode '{ble_mode}' *********")
        ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
        logger().info(f"ble_client_address: {ble_client_address}, ble_dut_address: '{ble_dut_address}'")
        time.sleep(3)

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        logger().info("Initiating wlan scan from DUT")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_BSSID:'{ap_bssid}'")

        logger().info("Validating sniffer packets before rejoin process")
        verify_sniffer_valiadation(wifi_sniffer, dut_mac_address, ap_bssid)

        logger().info("\n\n*************** Initiating TCP data transfer from DUT to remote server ***************\n")
        logger().info("Starting TCP server socket remotely")
        tcp_port = randint(6000, 6100)
        remote_socket.interfaces.socket.time_limit = 3000
        logger().info("Starting TCP Server socket at remote device")
        remote_socket.interfaces.socket.start_server(socket_type=0, port=tcp_port)  # 0-TCP, 1-UDP
        server_port = remote_socket.interfaces.socket.server_port

        logger().info("Opening TCP client socket in DUT")
        tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        logger().info(f"Socket open successfully : {tcp_socket_id}")
        time.sleep(5)

        logger().info(f"Setting Socket Options TCP_MAX_RETRY:{SocketOptions.TCP_MAX_RETRY} on DUT")
        wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        logger().info("Initiating TCP socket connection from DUT")
        socket_connect(wifi_dut, remote_socket, tcp_socket_id, device_ip, server_port, tcp_port)

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting sniffer capture to tcp packets")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_tcp_packets")
        time.sleep(3)

        ap_power_off = 0
        num_of_packets = 500
        for packet in range(1, num_of_packets):
            if packet == num_of_packets / 2:
                ap_power_off = 1

            if ap_power_off:
                logger().info("\n\n ***************** AP Turn OFF Thread execution starts *****************")
                t1 = ap_turn_off_on_thread(wifi_access_point, wifi_dut, rs_helper, device_ip, wifi_sniffer,
                                           dut_mac_address, switch=switch)
                t1.start()
                t1.wait_for_exit(True)
                ap_power_off = 0
                time.sleep(3)

            data = text_generator(size=1460)
            send_data_length = len(data)
            wifi_dut.interfaces.wifi.send(tcp_socket_id, send_data_length)

            logger().info("Validating received data on remote server")
            data_received = remote_socket.interfaces.socket.recv_data_tcp(send_data_length)
            assert send_data_length == len(
                data_received), "data length sent by DUT and received on remote peer is not matching"
            logger().info("data sent by DUT and received on remote peer is matching")
        logger().info("******************************* TCP data transfer completed ******************************")

        time_duration = utf_constants.get("time_duration")
        time_minutes = round((time_duration / 60), 2)
        logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
        time.sleep(time_duration)
        check_connection_status(wifi_dut, ble=True, wlan=True)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n\nChecking sniffer packets to verify rejoin process ")
        # Validate association request and association response packets
        packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'
        logger().info("Validating association request and association response packets")
        status = wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter2)['packet_count']
        if not status:
            logger().error('Unable to find association request and association response packets')

        logger().info(f"Disconnect from Remote device which is Master")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(10)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address)


@pytest.mark.skip()
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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "cipher": "AES"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.remote_socket("raspi_ip_socket")
# In raspi_ip_socket section of harness file interface needs to updated according to the raspi interface which is connected to AP.
def test_udp_functionality_while_rejoin_c20226(switch, utf_constants, rs_helper, wifi_access_point, wifi_sniffer,
                                               recovery, wifi_dut, ble_client, remote_socket):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    ble_client_address = None
    try:
        testcase = "test_UDP_functionality_while_rejoin_C20226"
        logger().info("testcase : UDP data transfer functionality while STA is in rejoin process")

        logger().info("Setting Rejoin Parameters in DUT")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        ble_mode = "ble_slave"
        logger().info(f"********* Initiating BLE test with DUT mode '{ble_mode}' *********")
        ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
        logger().info(f"ble_client_address: {ble_client_address}, ble_dut_address: '{ble_dut_address}'")
        time.sleep(3)

        logger().info("configuring the Sniffer with the channel")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("start capturing with Sniffer by giving the test case name as filename")
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(3)

        logger().info("Initiating wlan scan from DUT")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_BSSID:'{ap_bssid}'")

        logger().info("Validating sniffer packets before rejoin process")
        verify_sniffer_valiadation(wifi_sniffer, dut_mac_address, ap_bssid)

        logger().info("\n\n*************** Initiating UDP data transfer from DUT to remote server ***************\n")
        logger().info("Starting UDP server socket at remote device")
        udp_port = randint(5001, 6000)
        remote_socket.interfaces.socket.time_limit = 3000
        remote_socket.interfaces.socket.start_server(socket_type=1, port=udp_port)  # 0-TCP, 1-UDP
        server_port = remote_socket.interfaces.socket.server_port
        server_ip = remote_socket.interfaces.socket.hostname_or_ip_address()

        logger().info("Opening UDP client socket in DUT")
        udp_socket_id = wifi_dut.interfaces.wifi.open_udp_client_socket(socket_flag=SocketType.ASYNCHRONOUS)
        logger().info(f"Successfully opened UDP client socket on DUT with socket id:'{udp_socket_id}'")

        logger().info("Initiating UDP socket connection from DUT")
        socket_connect(wifi_dut, remote_socket, udp_socket_id, device_ip, server_port, udp_port)

        wifi_sniffer.interfaces.capture.configure_interface(
            channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Starting sniffer capture to udp packets")
        wifi_sniffer.interfaces.capture.start_capture(capture_file="rejoin_udp_packets")
        time.sleep(3)

        ap_power_off = 0
        num_of_packets = 500
        for packet in range(1, num_of_packets):
            if packet == num_of_packets / 2:
                ap_power_off = 1

            if ap_power_off:
                logger().info("\n\n ***************** AP Turn OFF Thread execution starts *****************")
                t1 = ap_turn_off_on_thread(wifi_access_point, wifi_dut, rs_helper, device_ip, wifi_sniffer,
                                           dut_mac_address, switch=switch)
                t1.start()
                t1.wait_for_exit(True)
                ap_power_off = 0
                time.sleep(3)

            data = text_generator(size=1460)
            send_data_length = len(data)

            wifi_dut.interfaces.wifi.send_to(udp_socket_id, send_data_length, server_ip, server_port)

            logger().info("Validating received data on remote server")
            data_received, _ = remote_socket.interfaces.socket.recv_data_udp(send_data_length)
            assert send_data_length == len(
                data_received), "data length sent by DUT and received on remote peer is not matching"
            logger().info("data sent by DUT and received on remote peer is matching")
        logger().info("******************************* UDP data transfer completed ******************************")

        time_duration = utf_constants.get("time_duration")
        time_minutes = round((time_duration / 60), 2)
        logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
        time.sleep(time_duration)
        check_connection_status(wifi_dut, ble=True, wlan=True)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("\n\nChecking sniffer packets to verify rejoin process")
        # Validate association request and association response packets
        packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'
        logger().info("Validating association request and association response packets")
        status = wifi_sniffer.interfaces.capture.sniffer_validation(True, packet_filter2)['packet_count']
        if not status:
            logger().error('Unable to find association request and association response packets')

        logger().info(f"Disconnect from Remote device which is Master")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(10)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address)


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
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config("wifi_access_point", wifi={"security": "WPA2", "cipher": "AES"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_read_char_value_of_remote_ble_when_wlan_is_in_connected_state_c20188(firmware_loader, utf_constants, rs_helper,
                                                                              wifi_sniffer, recovery, wifi_access_point,
                                                                              wifi_dut, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    ble_client_address = None
    try:
        logger().info(
            "testcase : Read the characteristic value by UUID of remote BLE device when WLAN is in connected state")

        time_duration = utf_constants.get("time_duration")
        capture_filename = "test_c20188"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
        time.sleep(3)

        logger().info("start ble GATT service in DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert ble_dut_address, "Unable to find ble_dut_address"
        time.sleep(3)

        scan_success, connect_success = False, False
        for count in range(5):
            try:
                if not scan_success:
                    ble_client.interfaces.bluetooth.close()
                    time.sleep(2)
                    service_class = ["HeartRateService"]
                    logger().info("Configuring heart rate profile with advertising on remote device")
                    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address,
                                                                                       service_classes=service_class)
                    time.sleep(3)
                    logger().info("Start scanning and connect to ble client")
                    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
                    wifi_dut.interfaces.wifi.ble_stop_scanning()
                    time.sleep(5)
                    scan_success = True
                if not connect_success:
                    logger().info(f"Initiating connection this can take some time...")
                    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
                    connect_success = True
                    time.sleep(5)
                    logger().info(f"BLE master connection successful from DUT...")
                    break
            except Exception as err:
                logger().info("*************** Exception block for stop advertising and stop scanning ***************")
                ble_client.interfaces.bluetooth.stop_advertising()
                ble_client.interfaces.bluetooth.close()
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                if count == 4:
                    raise err
        assert connect_success, "DUT BLE failed to connect to remote device"

        logger().info("Fetching HeartRateService profile from RD1")
        uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, timeout=30)
        assert HeartRateService.UUID.lower() in uuids, "Unable to get HeartRateService profile of RD from DUT"

        start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(
            ble_remote_dev_address=ble_client_address, uuid=int(HeartRateService.UUID, 16))
        assert start_handle, "Unable to fetch the RD address"
        assert end_handle, "Unable to get HeartRateService profile from RD"

        # Rasied Jira for below API: https://jira.silabs.com/browse/WIFI_BT_UTFHELP-1576
        logger().info("Getting characteristics value of heart rate profile by passing uuid of service class")
        wifi_dut.interfaces.wifi.ble_get_char_value_by_uuid(ble_client_address, start_handle, end_handle,
                                                            uuid=int("0x2A38", 16))

        logger().info("Initiating wlan scan from DUT")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        dut_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {dut_ip}, {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        time_minutes = round((time_duration / 60), 2)
        logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
        time.sleep(time_duration)
        check_connection_status(wifi_dut, ble=True, wlan=True)

        logger().info("Validating sniffer packets")
        verify_sniffer_valiadation(wifi_sniffer, dut_mac_address, ap_bssid)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address)
