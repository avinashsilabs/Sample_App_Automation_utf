import time
import pytest
import uuid
import re
import datetime
from random import randint
from datetime import datetime
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.utils import get_tls_certificate_dir
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.iperf.iperf_constants import IperfConstants, IperfTrafficType
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, \
    RS9116CustomFeatureBitMap, SocketOptions, RS9116ExtTCPIPFeatureBitMap, RS9116ConfigFeatureBitMap, DeviceConstants, RS9116CertificateType

"""
    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC)

    Author: Vishakha
"""

ping_count = 30

def logger():
    return get_logger(__name__)


def receive_data_socket(remote_socket, no_of_pkts, data_size, proto_type=0):
    fail_count = 0
    rcv_data = 0
    if proto_type == 0:
        remote_socket.interfaces.socket.set_recv_timeout(socket_type=0)
    else:
        remote_socket.interfaces.socket.set_recv_timeout(use_client_socket=True, socket_type=1)
    for count in range(0, no_of_pkts):
        if proto_type == 0:
            data = remote_socket.interfaces.socket.recv_data_tcp(data_size)
        else:
            data, address = remote_socket.interfaces.socket.recv_data_udp(data_size)
        if not isinstance(data, str):
            fail_count = fail_count + 1
            if fail_count == 5:
                break
            else:
                continue
        rcv_data = rcv_data + len(data)
    logger().info(f"Total bytes received on socket opened remotely -> {rcv_data}")
    return rcv_data


class receive_data_socket_thread(ThreadBase):
    def __init__(self, remote_socket, no_of_pkts, data_size, proto_type=0):
        super().__init__()
        self.remote_socket = remote_socket
        self.no_of_pkts = no_of_pkts
        self.data_size = data_size
        self.proto_type = proto_type

    def run(self):
        recv_data = receive_data_socket(self.remote_socket, self.no_of_pkts, self.data_size, self.proto_type)
        return recv_data

def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True,
                     expected="RSI_BLE_ENCRYPT_STARTED_EVENT", skip_scan=False):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        if start_needed:
            logger().info(f"Set up DUT for BLE master role")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            logger().info("Started BLE in DUT")
            assert ble_dut_address, f"Unable to start ble"
        logger().info("Start ble client")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to start smp advertising "
        time.sleep(5)
        if not skip_scan:
            logger().info("Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        time.sleep(5)
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected, timeout=120)
        logger().info("BLE Connection success")

    if mode == "ble_slave":
        if start_needed:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to start ble"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"Unable to start smp scanning "
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (
                found_devices[wifi_dut.interfaces.wifi.ble_address]
                == wifi_dut.interfaces.wifi.ble_advertising_data
        ), "Could not able to find our DUT"
        logger().info(f"ble connect")
        conn_params = {"min_conn_interval": 40,
                       "max_conn_interval": 40,
                       "conn_latency": 0,
                       "supervision_timeout": 200}

        ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                min_conn_interval=conn_params["min_conn_interval"],
                                                max_conn_interval=conn_params["max_conn_interval"],
                                                conn_latency=conn_params["conn_latency"],
                                                supervision_timeout=conn_params["supervision_timeout"])
        logger().info(f"fetching the connection status after 60 secs of sleep")
        time.sleep(60)
    return ble_client_address, ble_dut_address


def packet_check(wifi_sniffer, logger, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                 capture_filename, mode=0) -> list:
    logger().info(f"%%%%%%%%%%%%%%%%%%%%%%%%%into packet_check")
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    result = []
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address}) && (wlan.addr == {ap_bssid})'
    wifi_sniffer.interfaces.capture.shell(
        f"tshark -nr {wifi_sniffer.interfaces.capture.remote_capture_file} -Y '{packet_filter1}' -T fields -e "
        f"frame.number -w "
        f"{wlan_filter_file}")
    with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp:
        sftp.get(wlan_filter_file, local_capture_file)
    for packet in wifi_sniffer.interfaces.capture.iter_packets(
            decrypt_packets=True,
            encryption_type="WPA-PWD",
            decryption_key=decryption_key,
            capture_file_filter=local_capture_file
    ):
        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            if layer_name == "tls":
                filtered_packet = str(packet)
                filtered_packet = filtered_packet.split("Layer ")
                tls_layer_pkt = ""
                ra_address = ""
                ta_address = ""
                logger().info(f"DUT_MAC_ADDRESS: {dut_mac_address},AP_BSSID: {ap_bssid}")
                for layerp in filtered_packet:
                    if ((re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp))
                            or (re.search(".*TLS:", layerp))):
                        if re.search(".*TLS:", layerp):
                            tls_layer_pkt = layerp
                        if re.search(".*Receiver address:", layerp) and re.search(".*Transmitter address:", layerp):
                            Received = re.compile(r'Receiver address: (([0-9a-fA-F]:?){12})')
                            receiver_address = re.search(Received, layerp).group()
                            ra_address = (re.search(Received, layerp).group(1)).lower()
                            Transmit = re.compile(r'Transmitter address: (([0-9a-fA-F]:?){12})')
                            Transmitter_address = re.search(Transmit, layerp).group()
                            ta_address = (re.search(Transmit, layerp).group(1)).lower()
                            dut_mac_address_mod = dut_mac_address.lower()
                            ap_bssid_mod = ap_bssid.lower()

                        if ((ra_address == dut_mac_address_mod or ra_address == ap_bssid_mod) and (
                                ta_address == dut_mac_address_mod or ta_address == ap_bssid_mod)) and tls_layer_pkt:
                            logger().info(f"{Transmitter_address}>>>>>>{receiver_address}")
                            logger().info(f"TLS HANDSHAKE PACKET: {tls_layer_pkt}")
                            result.append(str(tls_layer_pkt))
    return result


def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()


def dut_clean_up(wifi_dut):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT -------------------------------")
    try:
        logger().info("BLE disconnect from DUT")
        for device_address in wifi_dut.interfaces.wifi.ble_devices_address:
            try:
                wifi_dut.interfaces.wifi.ble_disconnect(device_address)
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
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed -------------------")



# WLAN TCP-Tx packet loss with LE advertising
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
@pytest.mark.parametrize("number_of_pkts", [500])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "close_sockets",
                                        "disassociated", "ble_stop_adv", "ble_stop_scan"])
def test_TCP_packet_loss_C20222(wifi_sniffer, wifi_dut, wifi_access_point, ble_client, remote_socket,
                                remote_socket_factory, number_of_pkts, rs_helper, utf_constants):
    try:
        validation = True
        logger().info("Initiate ble service in DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, "Unable to get ble_client_address"
        logger().info("Begin BLE Advertising on DUT")
        wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info("DUT is on BLE Advertising mode...")
        time.sleep(3)
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_TCP_packet_loss_C20222')
        time.sleep(5)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')
        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        # The below api parses DUTs IP address
        data_size = 1460
        # The below api parses DUTs IP address
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
        logger().info("Starting tcp server remotely at port number 5001")
        remote_socket.interfaces.socket.start_server()
        # DUT opens tcp client socket
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket()
        assert sock == 0, f"socket id received is wrong, expected is 0"
        logger().info(f"socket id received is {sock} which is expected")
        local_port = randint(5001, 6000)
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        # Socket binds at (device_ip, 5001) in DUT
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        # tcp socket opened in DUT connects to the tcp server
        wifi_dut.interfaces.wifi.connect_to_server(sock, remote_socket.interfaces.socket)
        recv_thread = receive_data_socket_thread(remote_socket, number_of_pkts, data_size, 0)
        recv_thread.start()
        result = wifi_dut.interfaces.wifi.set_tx_on_multiple_sockets(socket_list=1, data_len=1460,
                                                                    number_of_pkts = number_of_pkts,
                                                                    time_interval=550, timeout=600)
        recv_thread.wait_for_exit(True)
        received_data = recv_thread.return_value
        bytes_sent = result[0][0]
        logger().info(f"Number of bytes sent by dut {bytes_sent}")
        logger().info(f"received data : {received_data}")

        packet_loss = (((bytes_sent - received_data) / bytes_sent) * 100)
        logger().info(f"Packet loss {packet_loss}")
        assert packet_loss == 0, "Packet loss is not in tolerance level while DUT receiving the data"

        logger().info(f"Start scanning to ble client")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        logger().info("DUT BLE device found in Raspi BLE scan result")
        assert ble_client_address, f"Unable to start smp scanning "
        time.sleep(5)

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validate broadcast probe request from DUT
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'
        # Validate association request and association response packets
        packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

        logger().info("Validating probe request packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find probe request packets'

        logger().info("Validating association request and association response packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association request and association response packets'

        logger().info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data)
        try:
            result = wifi_dut.interfaces.wifi.close_socket(sock)
            assert b"success" in result, "unable to close opened tcp socket"
            remote_socket.interfaces.socket.socket_close_indication(1)
            logger().info("Successfully closed opened socket in the DUT")
            time.sleep(5)
        except:
            pass
        logger().info(f"Initiating Wi-Fi disconnection on DUT")
        wifi_dut.interfaces.wifi.leave()
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)



# Wlan Multicast data UDP_TX and UDP_RX when DUT connected as slave
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": 0,
    }
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["multicast_leave", "wifi_powersave_disable", "bt_powersave_disable",
                                         "disassociated", "ble_stop_adv", "ble_stop_scan"])
def test_Multicast_C20227(multicast_client, net_perf_client, protocol, wifi_sniffer, wifi_dut,
                          wifi_access_point, wifi_client, ble_client, utf_constants, rs_helper):
    validation = True
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Multicast_C20227')
    time.sleep(5)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Joining into Wi-Fi")
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    timeout = 60
    multicast_TX = rs_helper.run_multicast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                                   multicast_client, traffic_type="TX")
    logger().info(f"Multicast send data :{multicast_TX}")
    time.sleep(15)
    multicast_RX = rs_helper.run_multicast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                                   multicast_client, traffic_type="RX")
    logger().info(f"Multicast receive data :{multicast_RX}")

    logger().info("Get ble device state")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Ble device is not connected"
    logger().info(" Connected to the BLE device ")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # Validate broadcast probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'
    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'
    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()


# WLAN Broadcast TX when DUT connected as slave
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "band": 0,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "ble_stop_adv", "ble_stop_scan"])
def test_Broadcast_C20228(net_perf_client, protocol, wifi_sniffer, wifi_dut, wifi_access_point,
                          wifi_client, ble_client, utf_constants, rs_helper):
    validation = True
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f" ====== configuring the sniffer with access point channel ====== ")
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Broadcast_C20228')
    time.sleep(5)
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Joining into Wi-Fi")
    device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Remote device ip :{host_ip}")
    timeout = 60
    broadcast_TX = rs_helper.run_broadcast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                                   traffic_type="TX")
    logger().info(f"Broadcast send data :{broadcast_TX}")
    time.sleep(15)
    broadcast_RX = rs_helper.run_broadcast_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout=80,
                                                   traffic_type="RX")
    logger().info(f"Broadcast receive data :{broadcast_RX}")

    logger().info("Get ble device state")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Ble device is not connected"
    logger().info(" Connected to the BLE device ")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'
    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info(f"Initiating Wi-Fi disconnection on DUT")
    wifi_dut.interfaces.wifi.leave()



# WiFi SSL Tx functionality and stability after BLE connection
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.EnahanceMaxPsp | RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.parametrize("cert1",
                         [
                             ["ca-chain.cert.pem", "mosquitto-utf.silabs.com.cert.pem",
                              "mosquitto-utf.silabs.com.key.pem"],
                         ]
                         )
@pytest.mark.end_state("wifi_dut",
                       wifi=["close_sockets", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan"])
def test_wifi_ssl_tx_and_stability_C20231(ssl_server, cert1, protocol, wifi_sniffer, wifi_dut, wifi_access_point,
                                          ble_client, utf_constants, rs_helper):
    try:
        validation = True
        ble_mode = "ble_slave"
        logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
        ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)
        capture_file = 'test_wifi_ssl_tx_and_stability_C20231'
        logger().info(f" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_wifi_ssl_tx_and_stability_C20231')
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        # Join Wi-Fi Access Point
        logger().info("Joining into Wi-Fi")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        logger().info(f"device_ip, device_mac : {device_ip}, {dut_mac_address}")

        port1 = ssl_server.interfaces.ssl.config['device_port1']
        ssl_server.interfaces.ssl.start_server(port=port1, server_cert=cert1[1])
        wifi_dut.interfaces.wifi.set_ssl_certificate(RS9116CertificateType.SSLCACertificate,
                                                     str(get_tls_certificate_dir().joinpath(cert1[0])),
                                                     cert_index=0,
                                                     )
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        # Enable ssl option for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        # Enable cert index 0 for socket opened
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   SocketOptions.CERT_INDEX0)

        wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
        wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)
        pkt_count = 4000
        buffer_length = 1370
        bytes_sent = (pkt_count * buffer_length)
        ssl_server.interfaces.ssl.data_receive(1, pkt_count, buffer_length)
        wifi_dut.interfaces.wifi.send_data_pkts(0, buffer_length, pkt_count)
        time.sleep(10)
        bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
        assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                             f"not matched on socket"
        # stop server
        ssl_server.interfaces.ssl.stop_server()

        logger().info("Get ble device state")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "Ble device is not connected"
        logger().info(" Connected to the BLE device ")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'
        snif_pkt_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        assert snif_pkt_count, "PS-POLL packets are not captured in the sniffer"
        logger().info(f"PS-POLL packets are captured in the sniffer")
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, ap_bssid, ["tls"], capture_file,
                               mode=0)

        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
            "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
            "Unable to find 'Change Cipher Spec' message"

        logger().info(f"Initiating Wi-Fi disconnection on DUT")
        wifi_dut.interfaces.wifi.leave()

    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut)

