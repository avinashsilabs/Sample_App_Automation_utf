import test_sta_ble_enterprise as sbe
from utf.utils.logger import get_logger
from typing import Dict
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
import pytest
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
    RS9116AsyncEventType,
    RS9116StoreConfiguration,
    RS9116CustomFeatureBitMap,
    RS9116MqttQos,
    DeviceConstants,
    RS9116OperatingMode,
    RS9116Band, RS9116PowerSaveProcedureTypes
    )
import time
from datetime import datetime
import uuid

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

class BleSlaveConn():
    def __init__(self, wifi_dut, ble_client, ble_dut_address=None, ble=True, wlan=True):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble = ble
        self.wlan = wlan

    def ble_slave_conection(self):
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(2)
        logger().info(f"Set up DUT for BLE advertising")
        self.ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert self.ble_dut_address, f"Unable to get ble_dut_address"
        try:
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            time.sleep(3)
            logger().info(f"Begin Scanning for BLE devices")
            ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=self.ble_dut_address)
            assert ble_client_address, f"Unable to get ble_client_address"
            time.sleep(5)
            self.ble_client.interfaces.bluetooth.stop_scanning()
            logger().info(f"See that we found our device")
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (found_devices[
                            self.wifi_dut.interfaces.wifi.ble_address] ==self.wifi_dut.interfaces.wifi.ble_advertising_data)
            logger().info("Connecting ble_client to DUT")
            conn_params = {"min_conn_interval": 40,
                               "max_conn_interval": 40,
                               "conn_latency": 0,
                               "supervision_timeout": 200}

            self.ble_client.interfaces.bluetooth.connect(dev_addr=self.ble_dut_address,
                                                        min_conn_interval=conn_params["min_conn_interval"],
                                                        max_conn_interval=conn_params["max_conn_interval"],
                                                        conn_latency=conn_params["conn_latency"],
                                                        supervision_timeout=conn_params["supervision_timeout"])
            logger().info("Connect ble_client to DUT successful")
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            self.ble_client.interfaces.bluetooth.stop_scanning()
            raise e
        # return self.ble_dut_address

    def disconnect(self):
        self.ble_client.interfaces.bluetooth.disconnect(self.ble_dut_address)

    def check_status(self):
        if self.ble:
            logger().info("Checking connection status of BLE")
            state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
            state_int = int(state) if state.isdigit() else -1
            assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
            logger().info("DUT is not disconnected from BLE")

        if self.wlan:
            logger().info("Checking connection status of Wi-Fi")
            events = self.wifi_dut.interfaces.wifi.get_async_events()
            disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
            count_disconnect = set()
            if len(disconnect_events):
                count_disconnect.add(str(disconnect_events[0]))
                logger().info(f"Disconnect Events:{count_disconnect}")
                assert False, f"DUT is not connected to Wi-Fi"
            assert len(disconnect_events) == 0
            logger().info(f"DUT is not disconnected from Wi-Fi during traffic run for long duration")

class SnifferValidation:
    def __init__(self, wifi_access_point, wifi_sniffer, ap_bssid, dut_mac_address, decryption_key=None, print_layers=None, capture_filename=None):
        super().__init__()
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.ap_bssid = ap_bssid
        self.dut_mac_address = dut_mac_address
        self.decryption_key = decryption_key
        self.print_layers = print_layers
        self.capture_filename = capture_filename


    def verify_sniffer_validation(self):
        validation = True
        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter2 = f"wlan.addr=={self.ap_bssid} && wlan.fc.type_subtype == 1 ||eapol"
        logger().info(f"validate PS-POLL frame with PM bit set to '1'")
        packet_filter3 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {self.dut_mac_address}) ' \
                     f'and (wlan.ra == {self.ap_bssid}))'
        logger().info(f"validate QOS data frame with more data bit set to '1'")
        packet_filter4 = f' (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {self.dut_mac_address}) ' \
                     f'and (wlan.ta == {self.ap_bssid}))'
        logger().info(
        f"Validating association, eapol from DUT"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '
        logger().info(
        f"Validating association, eapol from AP"
        )
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '
        logger().info('Validating PS Poll frames are sent from the device with power management bit')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Sniffer validation failed for ps-poll frame with PM bit 1'
        logger().info('Validating more data bit in QOS data frames')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Sniffer validation failed for QOS data frame with more data bit 1'
        logger().info(
        f"Validating DHCP frames from AP & DUT"
        )
        logger().info("passing passphrase and ssid to decrypt dhcp packets")
        decryption_key = f"{self.wifi_access_point.interfaces.wifi.passphrase}:{self.wifi_access_point.interfaces.wifi.ssid}"
        logger().info(f"decryption_key : {decryption_key}")
        logger().info("DHCP decryption is in progress...this may take some time")
        dhcp_list = self.wifi_sniffer.interfaces.capture.get_dhcp_list(self.dut_mac_address, decryption_key, ["dhcp"])
        logger().info(f"dhcp_list : {dhcp_list}")
        if dhcp_list is False:
            logger().info(f"\n\n***************Ignoring dhcp sniffer checks***********\n\n")
        else:
            logger().info("dhcp packets found in sniffer")




def get_tcp_pkt_list(wifi_sniffer, dut_mac_address, decryption_key: str, print_layers: list, capture_filename,
                     ) -> Dict[str, int]:
    tcp_capture_list = []
    tcp_layer = []
    ta_address = ""
    current_time = time.time()
    updated_capture_file = 'filter_' + capture_filename + '_' + str(
        datetime.fromtimestamp(current_time).strftime('%H_%M_%S'))
    file_name = f'./reports/{updated_capture_file}.pcap'
    local_capture_file = file_name
    wlan_filter_file = f"/tmp/{str(uuid.uuid4())[:8]}.pcap"
    packet_filter1 = f'(wlan.addr == {dut_mac_address})'
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
            if layer_name == "wlan":
                mac_layer = str(layer)
                for count in mac_layer.split("\n"):
                    if "Transmitter address" in count:
                        ta_address = count.split(": ")[1].strip()
            if layer_name in print_layers:
                tcp_layer = str(layer)
                tcp_capture_list.append(tuple([tcp_layer, ta_address, packet.sniff_timestamp]))
    return tcp_capture_list, tcp_layer


class Cleanup:
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def dut_clean_up(self):
        logger().info("\n\n ---------------------------- Cleaning UP the DUT -------------------------------")
        try:
            logger().info("BLE disconnect from DUT")
            for device_address in self.wifi_dut.interfaces.wifi.ble_devices_address:
                try:
                    self.wifi_dut.interfaces.wifi.ble_disconnect(device_address)
                except:
                    pass
            logger().info("Closing all opened sockets")
            self.wifi_dut.interfaces.wifi.close_sockets()
            logger().info("Disconnect from AP")
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_dut.interfaces.wifi.associated = False
            time.sleep(3)
        except:
            logger().info("******* Recovering the DUT using reset **********")
            self.wifi_dut.interfaces.wifi.reset()
            time.sleep(20)
        logger().info("\n ---------------------------- Cleaning UP of DUT is Completed -------------------")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features":  RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Verify_UDP_Tx_and_TCP_Tx_after_BLE_as_slave_C133475(wifi_dut, ble_client, wifi_access_point, utf_constants, wifi_client, wifi_sniffer, net_perf_client, rs_helper):
    logger().info("*******************C133475************************")
    clean_obj = Cleanup(wifi_dut)
    ble_obj = BleSlaveConn(wifi_dut, ble_client, ble_dut_address=None)
    try:
        capture_filename = "sta + ble_C133475"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        ble_mode = "ble_slave"
        logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
        ble_obj.ble_slave_conection()
        logger().info(f"**********initiating wlan connection*******************")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sniffer_obj = SnifferValidation(wifi_access_point, wifi_sniffer, ap_bssid, dut_mac_address, decryption_key=None, print_layers=None, capture_filename=None)
        timeout = 100
        protocols = [IperfConstants.TCP, IperfConstants.UDP]
        for retry_count in range(5):
            try:
                for protocol in protocols:
                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                          traffic_type="TX")
                break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)
        device_port = net_perf_client.interfaces.net_perf.server_port
        logger().info(f"port:{device_port-1}")
        ble_obj.check_status()
        time.sleep(5)
        logger().info(f"Disconnection from AP")
        wifi_dut.interfaces.wifi.leave(timeout=10)
        logger().info(f"Initiating BLE disconnection")
        ble_obj.disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        tcp_capture_list, tcp_layer = get_tcp_pkt_list(wifi_sniffer, dut_mac_address, decryption_key, ["tcp"],
                                    capture_filename)
        if not len(tcp_capture_list):
           logger().info(f"TCP packets are not captured ")
        check_port = "Source Port: " + str(device_port-1)
        for count in tcp_capture_list:
            if check_port in count[0]:
                logger().info(f"tcp port found")
                break
        sniffer_obj.verify_sniffer_validation()

    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        clean_obj.dut_clean_up()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features":  RS9116ExtCustomFeatureBitMap.IEEE802_11W | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Verify_UDP_rx_and_TCP_rx_after_BLE_as_slave_C133476(wifi_dut, wifi_access_point, wifi_sniffer, ble_client, rs_helper, utf_constants, wifi_client, net_perf_client):
    logger().info("*******************C133476************************")
    clean_obj = Cleanup(wifi_dut)
    ble_obj = BleSlaveConn(wifi_dut, ble_client)
    try:
        capture_filename = "tcp_tcp_udp_rx + ble_C133476"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=capture_filename)
        ble_mode = "ble_slave"
        logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
        ble_obj.ble_slave_conection()
        logger().info(f"**********initiating wlan connection*******************")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sniffer_obj = SnifferValidation(wifi_access_point, wifi_sniffer, ap_bssid, dut_mac_address)
        timeout = 100
        protocols = [IperfConstants.TCP, IperfConstants.UDP]
        for retry_count in range(5):
            try:
                for protocol in protocols:
                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout, traffic_type="RX")
                break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)
        device_port = net_perf_client.interfaces.net_perf.client_port
        logger().info(f"port:{device_port - 1}")
        ble_obj.check_status()
        logger().info(f"Disonnection from AP")
        wifi_dut.interfaces.wifi.leave(timeout=10)
        logger().info(f"Initiating BLE disconnection")
        logger().info(f"Initiating BLE disconnection")
        ble_obj.disconnect()
        time.sleep(5)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        decryption_key = f"{wifi_access_point.interfaces.wifi.passphrase}:{wifi_access_point.interfaces.wifi.ssid}"
        tcp_pkt_list, tcp_layer = get_tcp_pkt_list(wifi_sniffer, dut_mac_address, decryption_key, ["tcp"],
                                    capture_filename)
        if not len(tcp_layer):
            logger().info(f"TCP packets are not captured or one of the 4-way handshake pkts are not captured in the "
                      f"sniffer file")
        check_port = "Source Port: " + str(device_port - 1)
        for count in tcp_layer:
            if check_port in count[0]:
                logger().info(f"tcp port found")
                break
        sniffer_obj.verify_sniffer_validation()

    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        clean_obj.dut_clean_up()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_Throughputs_in_open_security_mode_when_ble_is_in_connection_C133449(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, rs_helper, wifi_client, ble_client, net_perf_client):
    logger().info("*******************C133449************************")
    clean_obj = Cleanup(wifi_dut)
    ble_obj = BleSlaveConn(wifi_dut, ble_client)
    try:
        testcase = "thoughputs_openmode_rx + ble_connection"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        ble_mode = "ble_slave"
        logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
        ble_obj.ble_slave_conection()
        logger().info(f"**********initiating wlan connection*******************")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=False)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sniffer_obj = SnifferValidation(wifi_access_point, wifi_sniffer, ap_bssid, dut_mac_address)
        timeout = 100
        protocols = [IperfConstants.TCP, IperfConstants.UDP]
        for retry_count in range(5):
            try:
                for protocol in protocols:
                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                          traffic_type="RX")
                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                          traffic_type="TX")
                break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)
        ble_obj.check_status()
        logger().info(f"Disonnection from AP")
        wifi_dut.interfaces.wifi.leave(timeout=10)
        logger().info(f"Initiating BLE disconnection")
        ble_obj.disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_obj.verify_sniffer_validation()
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        clean_obj.dut_clean_up()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv"])
def test_TCP_Rx_packet_loss_with_LE_advertising_C133469(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, rs_helper, utf_constants, ble_client, net_perf_client):
    logger().info("*******************C133469************************")
    clean_obj = Cleanup(wifi_dut)
    try:
        testcase = "tcp_rx_packet_loss + ble_advertising"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        ble_obj = sbe.BleThread_Advertise(wifi_dut, ble_client)
        ble_obj.start()
        ble_obj.wait_for_exit()
        logger().info(f"**********initiating wlan connection*******************")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        sniffer_obj = SnifferValidation(wifi_access_point, wifi_sniffer, ap_bssid, dut_mac_address)
        timeout = 100
        protocol = IperfConstants.TCP
        for retry_count in range(5):
            try:
                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                          traffic_type="RX")
                    break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)
        ble_obj.stop_adv_scan()
        logger().info(f"Disonnection from AP")
        wifi_dut.interfaces.wifi.leave(timeout=10)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        sniffer_obj.verify_sniffer_validation()
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        clean_obj.dut_clean_up()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features":  RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "band": 0

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_Throughputs_in_wpa2_aes_mode_when_ble_is_in_connection_C133450(wifi_dut, wifi_access_point, wifi_sniffer,
                                    utf_constants, rs_helper, wifi_client, ble_client, net_perf_client):
    logger().info("*******************C133450************************")
    validation = True
    clean_obj = Cleanup(wifi_dut)
    ble_obj = BleSlaveConn(wifi_dut, ble_client)
    try:
        testcase = "thoughputs_wpa2_aes + ble_connection"
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        ble_mode = "ble_slave"
        logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
        ble_obj.ble_slave_conection()
        logger().info("Initiating wlan scan from DUT")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        logger().info(f"**********initiating wlan connection*******************")
        device_ip, dut_mac_address = rs_helper.check_wifi_connectivity(utf_constants, wifi_dut, wifi_access_point, power_save=False)
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {ap_bssid}")
        host_ip = wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"Remote device ip :{host_ip}")
        timeout = 10
        protocols = [IperfConstants.TCP, IperfConstants.UDP]
        for retry_count in range(5):
            try:
                for protocol in protocols:
                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                          traffic_type="TX")

                    rs_helper.run_traffic(wifi_dut, net_perf_client, protocol, device_ip, host_ip, timeout,
                                          traffic_type="RX")
                break
            except Exception as e:
                try:
                    net_perf_client.interfaces.net_perf.close_files()
                    net_perf_client.interfaces.net_perf.iperf_process.stop(5)
                except:
                    pass
                logger().info(f"Iperf process Failed...retry_count{retry_count + 1}")
                if retry_count == 4:
                    raise e
                time.sleep(10)
        ble_obj.check_status()
        logger().info(f"Disonnection from AP")
        wifi_dut.interfaces.wifi.leave(timeout=10)
        logger().info(f"Initiating BLE disconnection")
        ble_obj.disconnect()
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = f"wlan.addr=={dut_mac_address} && wlan.fc.type_subtype == 0 || eapol"
        packet_filter2 = f"wlan.addr=={ap_bssid} && wlan.fc.type_subtype == 1 || eapol"
        logger().info(
            f"Validating association, eapol from DUT"
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '
        logger().info(
            f"Validating association, eapol from AP"
        )
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '
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
    finally:
        logger().info(f"Disabling powersave")
        wifi_dut.interfaces.wifi.power_save(0, 0)
        wifi_dut.interfaces.wifi.bt_power_save(0, 0)
        clean_obj.dut_clean_up()

