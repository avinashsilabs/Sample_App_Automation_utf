import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.wifi import WlanError
from utf.interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from utf.interfaces.iperf.iperf_device_output_parser import Result
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
        self.bssid = self.wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP bssid {self.bssid}")
        self.dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {self.dut_mac_address}")
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
                result = self.wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(result, self.wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
                ip_fail = 0
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(1)
        assert ip_fail == 0, "ip setting in DUT has failed"

    def ps_ping(self):
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
        time.sleep(5)
        assert status == 1, "DUT not responding for ping request......"

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


class Blethread(ThreadBase):
    def __init__(self, wifi_dut, ble_client,  ble_mode=None, ble_dut_address=None, ble_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_dut_address = ble_dut_address
        self.ble_mode = ble_mode
        self.ble_address = ble_address

    def run(self):
        ble_master_slave(self.wifi_dut, self.ble_client, self.ble_mode)

def ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if ble_mode == "ble_master":
        logger().info(f"Start DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address is not None, f"failed to initiate ble in dut"
        logger().info(f"Start ble client")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address is not None, f"unable to fetch ble address"
        time.sleep(1)
        logger().info(f"Start scanning and connect to ble client")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=30)
        timeout = 120
        logger().info(f"Initiating connection this can take upto {timeout} seconds....")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=timeout)

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

class wifi_datatransfer(ThreadBase):

    def __init__(self, wifi_dut, \
                 wifi_access_point, wifi_client, \
                 net_perf_client, protocol=None, device_ip=None, host_ip=None, dut_mac_address= None, ap_bssid=None, timeout=60):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.net_perf_client = net_perf_client
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.host_ip = host_ip
        self.timeout = timeout
        self.dut_mac_address =dut_mac_address
        self.ap_bssid = ap_bssid

    def __print_throughput(self, iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run(self):
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host_ip : {host_ip}")
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=self.host_ip, device_ip=self.device_ip,
                                                             protocol=self.protocol)
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


class httppostThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path
        self.wifi_sniffer = wifi_sniffer

    def run(self):
        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi
        logger().info("API used to post the http data")
        logger().info("API used to post the http data")
        status, content = self.wifi_dut.interfaces.http.http_post(self.http_server.interfaces.http, "cgi-bin/cgi_example.py",
                                                             post_data="hellothisiaatestcaseforget")
        assert status, "failed to get http data"
        assert content, "failed to get http data"
        logger().info(status)
        logger().info(content)

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
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
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address is not None
    wifi_dut.interfaces.wifi.ble_start_advertising()
    logger().info(f"Begin Scanning for BLE devices")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address is not None
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if ble_dut_address in found_devices and \
                found_devices[ble_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found
    ble_client.interfaces.bluetooth.connect(ble_dut_address)
    time.sleep(2)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    time.sleep(5)
    logger().info("Initiating BLE connect and disconnect on DUT for 5 iterations")
    for i in range(1, iter_count):
        time.sleep(2)
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(1)
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        time.sleep(2)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info(f"Clean up activity")
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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_BG_SCAN_functionality_of_dut_when_dut_ble_in_scan_state_C20362(wifi_sniffer, wifi_dut, wifi_access_point, ble_client,  utf_constants):
    logger().info(f"************************C20362*********************")
    validation = True
    testcase = "bgscan+ble"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 63, 4, 2, 50, 50, 0)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    ping_count = utf_constants.get("ping_count")
    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"
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
    wifi_leave(wifi_dut)
    logger().info(f"Initiating BLE disconnection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info(
        f"Validating Probe req(Broadcast)"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'
    wifi_obj.sniffer_validation()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
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
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    t1 = wifi_datatransfer(wifi_dut, wifi_access_point, wifi_client, net_perf_client, protocol)
    t1.start()
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    for i in range(1, iter_count):
        time.sleep(2)
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(1)
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        time.sleep(2)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info(f"Initiating BLE disconnection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
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
    logger().info(f"**********joining*******************")
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
    time.sleep(3)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
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
        "features":  RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_tcpip_features": 0,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature256kBMemoryMode | RS9116ExtCustomFeatureBitMap.Feature320kBMemoryMode,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    }
)
@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"index_long_lf.html"})
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_http_post_functionality_when_ble_connection_C20340(wifi_dut, wifi_access_point, wifi_sniffer, http_server, index_path, ble_client, utf_constants):
    logger().info(f"************************C20340*********************")
    testcase = "http_post + ble_C20340"
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point,  utf_constants,  wifi_sniffer)
    post_obj = httppostThread(wifi_dut, wifi_access_point, http_server, index_path, wifi_sniffer)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    post_obj.start()
    ble_mode = "ble_slave"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    wifi_leave(wifi_dut)
    logger().info(f"Initiating BLE disconnection")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    post_obj.stop()
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
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_coex_functionality_ble_connection_as_a_master_C20183(wifi_dut, ble_client, wifi_access_point, wifi_sniffer,  utf_constants):
    logger().info(f"************************C20183*********************")
    testcase = "Coex_functionality + ble_C20183"
    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
    ble_mode = "ble_master"
    logger().info(f"ble mode : {ble_mode}")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
    logger().info(f"**********joining*******************")
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, wifi_sniffer, utf_constants)
    wifi_obj.join_get_ip()
    wifi_obj.ps_ping()
    check_connection_status(wifi_dut, wlan=True)
    check_connection_status(wifi_dut, ble=True)
    logger().info(f"Clean up activity")
    wifi_leave(wifi_dut)
    logger().info(f"Initiating BLE disconnection")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validating disassoc or deauth frame')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, 1), \
        "Unable to find de-auth or disassoc packets in sniffer"
    wifi_obj.sniffer_validation()

@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.OpenMode,
        "config_features": RS9116ConfigFeatureBitMap.Default | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_coex_functionality_ble_connection_as_a_slave_C20182(wifi_dut, ble_client, wifi_access_point, wifi_sniffer,  utf_constants):
    logger().info(f"************************C20182*********************")
    testcase = "Coex_functionality + ble_C20182"
    iter_count = utf_constants.get("iter_count")
    for i in range(0, iter_count):
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=testcase)
        ble_mode = "ble_slave"
        logger().info(f"ble mode : {ble_mode}")
        ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address=None)
        logger().info(f"**********joining*******************")
        wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer)
        wifi_obj.join_get_ip()
        wifi_obj.ps_ping()
        check_connection_status(wifi_dut, wlan=True)
        check_connection_status(wifi_dut, ble=True)
        logger().info(f"Clean up activity")
        wifi_leave(wifi_dut)
        logger().info(f"Initiating BLE disconnection")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()
        wifi_obj.sniffer_validation()


