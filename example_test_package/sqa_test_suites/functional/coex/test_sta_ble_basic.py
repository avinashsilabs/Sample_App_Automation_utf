import pytest
import threading
import uuid
from datetime import datetime
import re
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import (
    RS9116CoexMode,
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap,
    RS9116CertificateType,
    RS9116FeatureBitMap,
    RS9116ConfigFeatureBitMap,
    RS9116ExtCustomFeatureBitMap,
    RS9116PowerSaveModes,
    SocketOptions,
    SocketType,
    Cipher,
    DeviceConstants
)
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes, RS9116BTFeatureBitMap
import time
from utf.utils.thread_base import ThreadBase

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

    Author: Jyothi Nagireddy
"""

class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, bssid=None, dut_mac_address=None, device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants
        self.wifi_sniffer = wifi_sniffer
        self.bssid = bssid
        self.dut_mac_address = dut_mac_address
        self.device_ip = device_ip

    def join_get_ip(self):
        count_i = 4
        logger().info("Scanning to the Wifi Access Point")
        self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,
                                                   ssid=None)
        logger().info("***************Joining to the Wifi Access Point*****************")
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {self.bssid}")
        for count in range(1, count_i):
            try:
                ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
                self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                logger().info(f"Found device ip: {self.device_ip}")
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed...retry count -> {count}")
                time.sleep(1)
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {self.dut_mac_address}")
        return self.bssid, self.dut_mac_address, self.device_ip

    def ps_ping(self):
        ping_count = self.utf_constants.get("ping_count")
        logger().info(
            f"The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put")
        logger().info(f"DUT to power save in Wifi+bluetooth mode")
        enable_wifips = self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                            RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifips, f" unable to enable the wifips"
        enable_btps = self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_btps, f"unable to enable the btps"
        logger().info(f"Initiating ping to DUT ip {self.device_ip} after power save")
        status = ping(self.device_ip, ping_count)
        time.sleep(5)
        assert status == 1, "DUT not responding for ping request......"

    def sniffer_validation(self):
        validation = True
        packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {self.dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

        packet_filter2 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

        packet_filter3 = f"wlan.addr=={self.bssid} && wlan.fc.type_subtype == 1 ||eapol"

        packet_filter4 = f'wlan.da == {self.dut_mac_address} and wlan.ta == {self.bssid} and ' \
                         f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

        packet_filter5 = f'wlan.addr == {self.dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        logger().info(
            f"Validating Probe req(Broadcast)"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'

        logger().info(
            f"Validating association, eapol from DUT"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '

        logger().info(
            f"Validating association, eapol from AP"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '
        logger().info(f"Validating more data bit in QOS data frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find power management bit in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'
        logger().info(
            f"Validating DHCP frames from AP & DUT"
        )
        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        logger().info("DHCP decryption is in progress...this may take some time")
        dhcp_list = self.wifi_sniffer.interfaces.capture.get_dhcp_list(self.dut_mac_address, decryption_key, ["dhcp"])
        logger().info(f"dhcp_list : {dhcp_list}")
        assert dhcp_list, "DHCP packets not found"


def ble_disconnect(wifi_dut, ble_address):
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_address, timeout=30)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")

class Blethread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, disconnect=False, ble_mode=None, ble_dut_address=None, ble_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.disconnect = disconnect
        self.ble_dut_address = ble_dut_address
        self.ble_mode = ble_mode
        self.ble_address = ble_address

    def run(self):
        ble_client_address, ble_dut_address = ble_master_slave(self.wifi_dut, self.ble_client, self.ble_mode)
        logger().info(f"{ble_client_address}")
        logger().info(f"{ble_dut_address}")
        return ble_client_address, ble_dut_address


def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, ble_start=True,
                     expected="RSI_BLE_ENCRYPT_STARTED_EVENT",
                     skip_scan=False):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        if ble_start:
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
                    result = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
                    assert result, "Unable to find the ble client device"
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
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        if ble_start:
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
            logger().info(f"See that we found our device")
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            assert wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (found_devices[
                        wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data)
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
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            ble_client.interfaces.bluetooth.stop_scanning()
            raise e
    return ble_client_address, ble_dut_address


def ssl_client_connection( wifi_access_point, wifi_dut, ssl_server, rs_helper, utf_constants):
    pkt_count = ssl_server.interfaces.ssl.config["no_of_pkts"]
    buffer_length = ssl_server.interfaces.ssl.config["buffer_length"]
    port1 = ssl_server.interfaces.ssl.config["device_port1"]
    bytes_sent = pkt_count * buffer_length
    logger().info(f"bytes sent {bytes_sent}")
    rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
    logger().info(f"The below api parses DUTs IP address")
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger().info(f"Open ssl server socket in remote device")
    ssl_server.interfaces.ssl.start_server()
    logger().info(f"Open ssl server socket in remote device")
    ssl_server.interfaces.ssl.start_server(port=port1)
    logger().info(f"Open ssl client socket in the DUT")
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(
        protocol=SocketOptions.SSL_ENABLE
    )
    assert sock == 0, f"socket id received is wrong, expected is 0"
    wifi_dut.interfaces.wifi.set_socket_option(
        sock,
        SocketOptions.SOL_SOCKET,
        SocketOptions.SO_SSL_ENABLE,
        SocketOptions.SSL_ENABLE,
    )
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    wifi_dut.interfaces.wifi.connect_to_server(
        sock, ssl_server.interfaces.ssl, server_port=port1
    )
    socket = 1
    ssl_server.interfaces.ssl.data_receive(socket, pkt_count, buffer_length)
    if ssl_server.interfaces.ssl.config["type"] == "ssl.server.ssl_linux":
        if ssl_server.interfaces.ssl.socket_connection_status(socket):
            wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count)
            time.sleep(10)
            bytes_received = ssl_server.interfaces.ssl.data_receive_stats(socket)
            assert bytes_sent == bytes_received, (
                f"Number of bytes sent by DUT and received on the remote "
                f"peer not matched on socket {socket} "
            )
    wifi_dut.interfaces.wifi.close_socket(sock)
    ssl_server.interfaces.ssl.stop_server()


def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=60)
    logger().info(f"Leave completed in {t.duration} seconds")

def ble_non_connectable_adv_mode(wifi_dut, ble_client):
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, " failed to start ble"
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=ble_dut_address,
        hci_adv_params="0xA0 0x00 "  # Advertising_Interval_Min
                       "0xA0 0x00 "  # Advertising_Interval_Max
                       "0x03 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
    )
    assert bt_client_address is not None, "Unable to fetch bluetooth address from Remote device"
    time.sleep(1)
    logger().info(f"****** ADDING WHITELIST BEFORE SCANNING")
    wifi_dut.interfaces.wifi.ble_add_white_list(bt_client_address)
    logger().info(f"Start scanning and connect to ble client")
    scan_results = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, ble_scan_filter_type=1,
                                                timeout=120)
    logger().info(f" scan result : {scan_results}")
    scan_str = scan_results.decode("UTF-8")
    report_type_3 = False
    logger().info(f"{scan_str}")
    if "report_type:3" in scan_str:
        report_type_3 = True
    assert report_type_3, "unable to find report_type:3"
    logger().info(f"found report_type:3")
    time.sleep(2)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    ble_client.interfaces.bluetooth.stop_advertising()
    logger().info(f"Remote device found in scan results ,BLE scanning is successful")


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

class ConnectionStatus(ThreadBase):
    def __init__(self, wifi_dut, bt=False, ble=False, wlan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt = bt
        self.ble = ble
        self.wlan = wlan

    def run(self):
        check_connection_status(self.wifi_dut, self.ble, self.wlan)

class ble_continuous_scan_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_mode, ble_scan_interval=100, ble_scan_window=5
               ):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_mode = ble_mode
        self.ble_scan_interval = int(ble_scan_interval / 0.625)
        self.ble_scan_window = int(ble_scan_window / 0.625)

    def run(self):
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        logger().info(f"Start ble client")
        ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert ble_client_address is not None, "unable to get ble address"
        time.sleep(1)
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address,
                                                         ble_scan_interval=self.ble_scan_interval,
                                                         ble_scan_window=self.ble_scan_window, timeout=120)
        logger().info("ble_continuous_scan_thread completed")

class wifi_datatransfer(ThreadBase):

    def __init__(self, wifi_dut, \
                 wifi_access_point, wifi_client, \
                 net_perf_client, protocol=None, device_ip=None, host_ip=None, timeout=100):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip
        self.timeout = timeout

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run(self):
        self.device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip :{self.device_ip}")
        self.host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host_ip : {self.host_ip}")
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip,
                                                             protocol=self.protocol, time_out=self.timeout)
        self.net_perf_client.interfaces.net_perf.start()
        logger().info("sending data from DUT")
        logger().info(f"open socket and send traffic")
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            self.host_ip,
            self.device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )
        time.sleep(10)
        logger().info(f"get and print throughput")
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None, "Throughput not found"
        self.__print_throughput(tp)


def packet_check(wifi_sniffer, logger, decryption_key: str, dut_mac_address, ap_bssid, print_layers: list,
                 capture_filename, mode=0) -> list:
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

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connect_and_disconnect_functionality_of_dut_ble_in_slave_mode_while_sta_is_in_connection_C20263(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, ble_client):
    testcase = "sta+ble_C20263"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    iter_count = utf_constants.get("iter_count")
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    time.sleep(2)
    logger().info(f"**********Initiating wlan connection*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    time.sleep(5)
    for i in range(1, iter_count):
        logger().info(f"Initiating BLE connect and disconnect on DUT for '{i}' iteration")
        time.sleep(2)
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(1)
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[
                    wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info("BLE Connection success")
        time.sleep(60)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    logger().info(f"Disabling powersave")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(0, 0)
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Disassociating with the AP")
    wifi_leave(wifi_dut)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features":  RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_BG_SCAN_functionality_of_dut_when_dut_ble_in_connection_state_C20362(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,  utf_constants):
    logger().info(f"************************C20362*********************")
    validation = True
    testcase = "bgscan+ble"
    ping_count = utf_constants.get("ping_count")
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 63, 4, 2, 50, 50, 0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f"AP bssid {bssid}")
    result = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = result.ip.decode()
    logger().info(f"DUT ip address : {dut_ip}")
    logger().info(
        f"The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put")
    logger().info(f"DUT to power save in Wifi+bluetooth mode")
    enable_wifips = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifips, f" unable to enable the wifips"
    enable_btps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_btps, f"unable to enable the btps"
    logger().info(f"Initiating ping to DUT ip {dut_ip} after power save")
    ping(dut_ip, ping_count)
    time.sleep(5)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    logger().info(f"Disabling powersave")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(0, 0)
    logger().info("Disassociating with the AP")
    wifi_leave(wifi_dut)
    logger().info(f"Initiating BLE disconnection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"

    packet_filter2 = f"wlan.addr=={dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

    packet_filter3 = f"wlan.addr=={bssid} && wlan.fc.type_subtype == 1 ||eapol"

    packet_filter4 = f'wlan.da == {dut_mac_address} and wlan.ta == {bssid} and ' \
                     f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

    packet_filter5 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

    logger().info(
        f"Validating Probe req(Broadcast)"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'

    logger().info(
        f"Validating association, eapol from DUT"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '

    logger().info(
        f"Validating association, eapol from AP"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '
    logger().info(f"Validating more data bit in QOS data frames")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find power management bit in sniffer capture'

    logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
        'packet_count'], 'Unable to find ps polls in sniffer capture'
    logger().info(
        f"Validating DHCP frames from AP & DUT"
    )
    logger().info("passing passphrase and ssid to decrypt dhcp packets")
    decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
    logger().info(f"decryption_key : {decryption_key}")
    logger().info("DHCP decryption is in progress...this may take some time")
    dhcp_list = wifi_sniffer.interfaces.capture.get_dhcp_list(dut_mac_address, decryption_key, ["dhcp"])
    logger().info(f"dhcp_list : {dhcp_list}")
    assert dhcp_list, "DHCP packets not found"

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_functionality_of_BLE_for_disconnect_and_connect_multiple_times_When_STA_is_in_connection_C20341(wifi_dut, ble_client, wifi_access_point, wifi_sniffer, utf_constants, wifi_client, net_perf_client, protocol):
    logger().info(f"************************C20341*********************")
    testcase = "http post functionality with non existing ip +ble"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    iter_count = utf_constants.get("iter_count")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
    logger().info(f"**********Initiating wlan connection*******************")
    device_ip = wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    t1 = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, device_ip)
    t1.start()
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    for i in range(1, iter_count):
        logger().info(f"initiating ble connect and disconnect for '{i}' iteration")
        time.sleep(2)
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(1)
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[
                    wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info("BLE Connection success")
        time.sleep(60)
        check_connection_status(wifi_dut, ble=True)
    t1.wait_for_exit(True)
    logger().info(f"Stability check")
    logger().info(f"Disabling powersave")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(0, 0)
    check_connection_status(wifi_dut, wlan=True)
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info(f"Clean up activity")
    logger().info("Disassociating with the AP")
    wifi_leave(wifi_dut)
    t1.stop()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features":  RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "ext_custom_features": 0,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_with_nonexisting_ip_after_ble_connection_C20237(wifi_dut, ble_client, wifi_access_point, utf_constants, wifi_sniffer, http_server, index_path):
    logger().info(f"************************C20237*********************")
    testcase = "http post functionality with non existing ip +ble"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    logger().info(f"**********Initiating wlan connection*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
    with pytest.raises(WlanError) as exc_info:
        logger().info("fetching the data from  http server using get method")
        wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                               server_ip='192.168.9.99',
                                               post_data="hellothisisatestcase")
    assert exc_info.value.error_code == 0xBB38, "observed wrong error code expected is 0xBB38"
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    logger().info(f"Disabling powersave")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(0, 0)
    logger().info("Disassociating with the AP")
    wifi_leave(wifi_dut)
    logger().info(f"Initiating BLE disconnection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features":  RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_with_ble_connection_C20340(wifi_dut, wifi_access_point, wifi_sniffer, http_server, ble_client, utf_constants):
    logger().info(f"************************C20340*********************")
    testcase = "http_post + ble_C20340"
    iter_count = utf_constants.get("iter_count")
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"**********Initiating wlan connection*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point,  utf_constants,  wifi_sniffer)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    t1 = Blethread(wifi_dut, ble_client, ble_mode=ble_mode)
    t1.start()
    t1.wait_for_exit()
    for count in range(1, iter_count):
        logger().info(f"******************* iteration {count}  ********************* ")
        wifi_dut.interfaces["http"] = wifi_dut.interfaces.wifi
        logger().info("sends data to http server using post method")
        status, content = wifi_dut.interfaces.http.http_post(http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellotestingfrohttppostcontent")
        assert status, "failed to post data"
        logger().info(status)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    logger().info(f"Disabling powersave")
    wifi_dut.interfaces.wifi.power_save(0, 0)
    wifi_dut.interfaces.wifi.bt_power_save(0, 0)
    logger().info("Disassociating with the AP")
    wifi_leave(wifi_dut)
    ble_client_address, ble_dut_address = t1.return_value
    logger().info(f"Initiating BLE disconnection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_coex_functionality_ble_connection_as_a_master_C20183(wifi_dut, ble_client, wifi_access_point, wifi_sniffer,  utf_constants):
    logger().info(f"************************C20183*********************")
    try:
        testcase = "Coex_functionality + ble_C20183"
        iter_count = utf_constants.get("iter_count")
        validation = True
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
        for i in range(1, iter_count+1):
            logger().info(f"iteraton: '{i}'")
            ble_mode = "ble_master"
            logger().info(f"ble mode : {ble_mode}")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
            logger().info(f"**********Initiating wlan connection*******************")
            bssid, dut_mac_address, device_ip = wifi_obj.join_get_ip()
            logger().info(f"dut_mac_address: {dut_mac_address}")
            wifi_obj.ps_ping()
            check_connection_status(wifi_dut, wlan=True, ble=True)
            time.sleep(3)
            logger().info("Disassociating with the AP")
            wifi_leave(wifi_dut)
            logger().info(f"Initiating BLE disconnection")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        dut_mac_address = wifi_obj.return_value
        packet_filter1 = f'((wlan.addr == {dut_mac_address}) && (wlan.fc.type_subtype == 10 || wlan.fc.type_subtype == 12))'
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('Validating disassoc or deauth frame')
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1), \
            "Unable to find de-auth or disassoc packets in sniffer"
        wifi_obj.sniffer_validation()

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_coex_functionality_ble_connection_as_a_slave_C20182(wifi_dut, ble_client, wifi_access_point, wifi_sniffer,  utf_constants):
    logger().info(f"************************C20182*********************")
    try:
        testcase = "Coex_functionality + ble_C20182"
        iter_count = utf_constants.get("iter_count")
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
        for i in range(1, iter_count+1):
            logger().info(f"iteration '{i}'")
            ble_mode = "ble_slave"
            logger().info(f"ble mode : {ble_mode}")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
            logger().info(f"**********Initiating wlan connection*******************")
            wifi_obj.join_get_ip()
            wifi_obj.ps_ping()
            check_connection_status(wifi_dut, wlan=True)
            check_connection_status(wifi_dut, ble=True)
            time.sleep(3)
            logger().info("Disassociating with the AP")
            wifi_leave(wifi_dut)
            logger().info(f"Initiating BLE disconnection")
            ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        dut_clean_up(wifi_dut)




@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "band": 0,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_deinit_init_functionality_of_ble_C20326(wifi_dut, ble_client, wifi_access_point, wifi_sniffer,  utf_constants):
    logger().info(f"************************C20236*********************")
    try:
        testcase = "Coex_functionality + ble_C20236"
        iteration_count = utf_constants.get("iter_count")
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        time.sleep(5)
        logger().info(f"**********Initiating wlan connection*******************")
        wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
        wifi_obj.join_get_ip()
        wifi_obj.ps_ping()
        for i in range(1, iteration_count + 1):
            logger().info(f"iteration: '{i}'")
            ble_mode = "ble_master"
            logger().info(f"ble mode : {ble_mode}")
            logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
            ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
            logger().info(f" BLE Disconnection")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=10)
            logger().info("De initialising BLE")
            wifi_dut.interfaces.wifi.ble_initialized = False
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()

    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
      wifi={
          "oper_mode": 0,
          "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
          "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
          "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
          "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
          "ext_custom_features": RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
          "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
          "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
          "ca_cert": "ca-chain.cert.pem",
          "set_send_feature_frame": True,
        },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                           wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ssl_ble_connection_as_master_C20356(wifi_dut, wifi_sniffer, wifi_access_point, ssl_server, ble_client, rs_helper, utf_constants):
    logger().info("**************testcase : C20356*******************")
    try:
        channel = wifi_access_point.interfaces.wifi.channel
        testcase = "sta+ble_ssl_connection"
        validation = True
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        ble_mode = "ble_master"
        ble_obj = Blethread(wifi_dut, ble_client, ble_mode=ble_mode)
        ble_obj.start()
        ssl_client_connection(
         wifi_access_point, wifi_dut, ssl_server, rs_helper, utf_constants)
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {bssid}")
        ble_client_address, _ = ble_obj.return_value
        logger().info(f"Stability check -->ping to dut successful")
        check_connection_status(wifi_dut, wlan=True, ble=True)
        logger().info("Disassociating with the AP")
        wifi_dut.interfaces.wifi.leave()
        ble_obj.wait_for_exit()
        logger().info(f"Disconnect from DUT Master")
        wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        # Validate probe request from DUT
        packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

        # Validate association request and association response packets
        packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {bssid} && wlan.fc.type_subtype == 1) || eapol)'

        # Validate qos data packets should be observed with more data bit set to 1
        packet_filter3 = f'(wlan.ta == {bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

        # Validate PS Polls with power management Bit set to 1
        packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

        logger().info("Validating probe request packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find probe request packets'

        logger().info("Validating association request and association response packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association request and association response packets'

        logger().info("Validating qos data packets should be observed with more data bit set to 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

        logger().info("Validating PS Polls with power management Bit set to 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"DECRYPTION KEY-->{decryption_key}")
        ssl_pkt = packet_check(wifi_sniffer, logger, decryption_key, dut_mac_address, bssid, ["tls"], testcase)
        assert (message for message in ssl_pkt if "Client Hello" in ssl_pkt), "Unable to find 'Client Hello' message"
        assert (message for message in ssl_pkt if "Server Hello" in ssl_pkt), "Unable to find 'Server Hello' message"
        assert (message for message in ssl_pkt if "Client Key Exchange" in ssl_pkt), \
         "Unable to find 'Client Key Exchange' message"
        assert (message for message in ssl_pkt if "Change Cipher Spec" in ssl_pkt), \
        "Unable to find 'Change Cipher Spec' message"

    finally:
        logger().info(f"Clean up activity")
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        dut_clean_up(wifi_dut)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1 | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.EXT_FEAT_XTAL_CLK_ENABLE | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.end_state("wifi_dut", wifi=["ble_stop_adv"])
def test_sta_ble_non_connectable_Adv_C20331(wifi_dut, wifi_access_point, utf_constants,  wifi_sniffer, wifi_client, ble_client):
    logger().info("**************testcase : C20331*******************")
    try:
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="sta+ble_non_connectable_adv")
        logger().info(f"**********Initiating wlan connection*******************")
        wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
        wifi_obj.join_get_ip()
        logger().info(f"configuring the remote device in non-connectable advertise mode")
        ble_non_connectable_adv_mode(wifi_dut, ble_client)
        wifi_obj.ps_ping()
        logger().info("Disassociating with the AP")
        wifi_leave(wifi_dut)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        dut_clean_up(wifi_dut)

@pytest.mark.config(
     "wifi_dut",
     wifi={
         "oper_mode": 0,
         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
         "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
         "custom_features": RS9116CustomFeatureBitMap.Default,
         "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
         "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
         "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
         "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
         "rejoin_max_retry": 0,
         "scan_interval": 4,
         "beacon_missed_count": 40,
         "first_time_retry": 0
     },
 )
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "beacon_interval": 200})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_coex_functionality_wlan_connection_while_ble_is_in_scan_state_C20184(wifi_dut, wifi_access_point, wifi_sniffer, ble_client, utf_constants, rs_helper):
    logger().info("**************testcase : C20184*******************")
    try:
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="sta+ble_C20184")
        ble_mode = "ble_master"
        t1 = ble_continuous_scan_thread(wifi_dut, ble_client, ble_mode, ble_scan_interval=100, ble_scan_window=5)
        t1.start()
        logger().info(f"**********Initiating wlan connection*******************")
        wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
        wifi_obj.join_get_ip()
        wifi_obj.ps_ping()
        logger().info("Disassociating with the AP")
        wifi_leave(wifi_dut)
        t1.wait_for_exit(True)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()
    finally:
        ble_client.interfaces.bluetooth.stop_advertising()
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        dut_clean_up(wifi_dut)

