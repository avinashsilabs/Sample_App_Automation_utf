from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.stopwatch import Stopwatch
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
import pytest
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.utils.iperf.iperf_utils import print_dict
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
import threading

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

def ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if ble_mode == "ble_master":
        logger().info(f"Set up DUT for BLE master role")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        logger().info("Started BLE in DUT")
        assert ble_dut_address, f"Unable to fetch ble dut address"
        logger().info("Start ble client")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        logger().info("Start scanning and connect to ble client")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
        logger().info("BLE Connection success")

    if ble_mode == "ble_slave":
        logger().info(f"Set up DUT for BLE advertising")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to find ble dut address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
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
        time.sleep(2)
    return ble_client_address, ble_dut_address

def ble_disconnect(wifi_dut, ble_address):
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_address, timeout=30)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")

class Blethread(ThreadBase):
    def __init__(self, wifi_dut, ble_client,  ble_mode=None, ble_dut_address=None, ble_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_mode = ble_mode
        self.ble_address = ble_address

    def run(self):
        ble_master_slave(self.wifi_dut, self.ble_client, self.ble_mode, ble_dut_address=None)
        ble_disconnect(self.wifi_dut, self.ble_address)

class WifiThread(ThreadBase):
     def __init__(self, wifi_dut, wifi_access_point, wifi_sniffer, utf_constants, bssid=None, dut_mac_address=None, device_ip=None, join_dut=None, ps_ping=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants
        self.wifi_sniffer = wifi_sniffer
        self.bssid = bssid
        self.device_ip = device_ip
        self.dut_mac_address = dut_mac_address
        self.join_dut = join_dut
        self.ps_ping = ps_ping


     def run(self):
            self.bssid = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"AP bssid {self.bssid}")
            self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {self.dut_mac_address}")
            count_i = 4
            for count in range(1, count_i):
                try:
                    scan_fail = 1
                    logger().info("Scanning to the Wifi Access Point")
                    self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,
                                                    ssid=None)
                    scan_fail = 0
                    break
                except:
                    logger().info(f"Scanning to the Wifi Access Point is failed. retry count -> {count}")
                    time.sleep(1)
            if scan_fail:
               logger().info(f"Scanning to the AP has failed")
               assert scan_fail == 0, "Scanning to the AP is failed"
            for count in range(1, count_i):
                try:
                    join_fail = 1
                    logger().info("***************Joining to the Wifi Access Point*****************")
                    self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                    join_fail = 0
                    break
                except:
                    logger().info(f"Joining to the Wifi Access point is failed. retry count -> {count}")
                    time.sleep(1)
            if join_fail:
             logger().info(f"Joining to the AP has failed")
             assert join_fail == 0, "Joining to the AP is failed"

            ip_fail = 1
            for count in range(1, count_i):
                 try:
                     ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
                     self.device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
                     logger().info(f"Found device ip: {self.device_ip}")
                     ip_fail = 0
                     break
                 except:
                     logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                     time.sleep(1)
            assert ip_fail == 0, "ip setting in DUT has failed"
            ping_count = self.utf_constants.get("ping_count")
            self.device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            logger().info(f"device ip:{self.device_ip}")
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
            assert status is True, "DUT is not responding to ping request from third party device"
            time.sleep(5)
     def sniffer_validation(self):
        validation = True
        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter2 = f"wlan.addr=={self.bssid} && wlan.fc.type_subtype == 1 ||eapol"
        logger().info(f"validate PS-POLL frame with PM bit set to '1'")
        packet_filter3 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {self.dut_mac_address}) ' \
                         f'and (wlan.ra == {self.bssid}))'
        logger().info(f"validate QOS data frame with more data bit set to '1'")
        packet_filter4 = f' (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {self.dut_mac_address}) ' \
                         f'and (wlan.ta == {self.bssid}))'
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
        assert dhcp_list, "DHCP packets not found"


class wifi_datatransfer(ThreadBase):

    def __init__(self, wifi_dut, \
                 wifi_access_point, wifi_client, \
                 net_perf_client, protocol=None, device_ip=None, dut_mac_address=None, ap_bssid=None, host_ip=None, run_rx=None, run_tx=None, timeout=60):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip
        self.timeout = timeout
        self.dut_mac_address = dut_mac_address
        self.ap_bssid = ap_bssid
        self.run_rx = run_rx
        self.run_tx = run_tx

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run(self):
        # self.device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        # logger().info(f"Found device ip :{self.device_ip}")
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host_ip : {host_ip}")

        if self.run_rx:
            logger().info(f"preparing iperf")
            self.net_perf_client.interfaces.net_perf.init_client(host_ip=self.host_ip, device_ip=self.device_ip, protocol=self.protocol)
            logger().info(f"creating results object for sharing between host and dut")
            result = Result(self.net_perf_client.interfaces.net_perf.protocol)
            logger().info(f"open socket and start listening")
            with self.wifi_dut.interfaces.wifi.start_socket_reader(
                  log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
                  result=result,
                  protocol=self.net_perf_client.interfaces.net_perf.protocol,
                  port=self.net_perf_client.interfaces.net_perf.client_port,
                  device_ip=self.device_ip,
                  data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
                  time=self.net_perf_client.interfaces.net_perf.client_timeout) as obj:
              logger().info(f"start iperf")
            self.net_perf_client.interfaces.net_perf.start()
            logger().info(f"capture device output")
            self.wifi_dut.interfaces.wifi.read_from_device(obj,
                                                           self.net_perf_client.interfaces.net_perf.client_timeout)
            time.sleep(10)
            logger().info(f"get and print throughput")
            tp = self.net_perf_client.interfaces.net_perf.process_output(result)
            assert tp is not None, "Throughput not found"

            self.__print_throughput(tp)

        if self.run_tx:
            self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip, protocol=self.protocol)
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


def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=60)
    logger().info(f"Leave completed in {t.duration} seconds")

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

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.Default,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_Throughputs_in_open_security_mode_when_ble_is_in_connection_C20203_1(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, utf_constants, ble_client, net_perf_client, protocol):
    logger().info("*******************C20203************************")
    testcase = "thoughputs_openmode_rx + ble_connection"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants)
    iperf_obj = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, run_rx=True)
    wifi_obj.start()
    iperf_obj.start()
    wifi_obj.wait_for_exit()
    iperf_obj.wait_for_exit()
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection on remote")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.Default,
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol",  [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_sta_Throughputs_in_open_security_mode_when_ble_is_in_connection_C20203_2(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, utf_constants, ble_client, net_perf_client, protocol):
    logger().info("*******************C20203************************")
    testcase = "thoughputs_openmode_tx + ble_connection"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants)
    iperf_obj = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol,run_tx=True)
    wifi_obj.start()
    iperf_obj.start()
    wifi_obj.wait_for_exit()
    iperf_obj.wait_for_exit()
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection on remote")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    wifi_obj.sniffer_validation()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_TCP_Rx_packet_loss_with_LE_advertising_C20223(wifi_dut, wifi_access_point, wifi_client, wifi_sniffer, utf_constants, ble_client, net_perf_client, protocol):
    logger().info("*******************C20223************************")
    testcase = "tcp_rx_packet_loss + ble_advertising"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(3)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants)
    iperf_obj = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, run_rx=True)
    wifi_obj.start()
    iperf_obj.start()
    wifi_obj.wait_for_exit()
    iperf_obj.wait_for_exit()
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if ble_dut_address in found_devices and \
                found_devices[ble_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, f"unable to find the device"
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Verify_UDP_Tx_and_TCP_Tx_after_BLE_as_slave_C20229(wifi_dut, ble_client, wifi_access_point, utf_constants, wifi_client, wifi_sniffer, net_perf_client, protocol):
    logger().info("*******************C20229************************")
    validation = True
    testcase = "sta + ble_C20229"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants)
    iperf_obj = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, run_tx=True)
    wifi_obj.start()
    iperf_obj.start()
    wifi_obj.wait_for_exit()
    iperf_obj.wait_for_exit()
    logger().info(f"Validate tcp port")
    packet_filter1 = f'tcp.port == 5001'
    logger().info(f"Validate udp port")
    packet_filter2 = f'udp.port == 5001'
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection on remote")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validating tcp port')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for tcp port'
    logger().info('Validating udp port')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Sniffer validation failed for udp port'
    wifi_obj.sniffer_validation()

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity | RS9116FeatureBitMap.ULPGPIOHandshake,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP, IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Verify_UDP_rx_and_TCP_rx_after_BLE_as_slave_C20230(wifi_dut, wifi_access_point, wifi_sniffer, ble_client, utf_constants, wifi_client, net_perf_client, protocol):
    logger().info("*******************C20230************************")
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    validation = True
    testcase = "tcp_tcp_udp_rx + ble_C20230"
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants)
    iperf_obj = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol, run_rx=True)
    wifi_obj.start()
    iperf_obj.start()
    wifi_obj.wait_for_exit()
    iperf_obj.wait_for_exit()
    logger().info(f"Validate tcp port")
    packet_filter1 = f'tcp.port == 5001'
    logger().info(f"Validate udp port")
    packet_filter2 = f'udp.port == 5001'
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info("Initiating BLE disconnection on remote")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validating tcp port')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for tcp port'
    logger().info('Validating udp port')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Sniffer validation failed for udp port'
    wifi_obj.sniffer_validation()


