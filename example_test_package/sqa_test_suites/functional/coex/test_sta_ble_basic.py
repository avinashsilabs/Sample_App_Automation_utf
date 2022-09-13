import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.utils.stopwatch import Stopwatch
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
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
import time

def logger():
    return get_logger(__name__)

class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, bssid=None, dut_mac_address=None, testcase=None, device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants
        self.wifi_sniffer = wifi_sniffer
        self.bssid = bssid
        self.dut_mac_address = dut_mac_address
        self.testcase = testcase
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

    def powersave_ping(self):
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
        ping(self.device_ip, ping_count)
        time.sleep(5)

    def sniffer_validation(self):
        validation = True
        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter2 = f"wlan.addr=={self.bssid} && wlan.fc.type_subtype == 1 ||eapol"
        packet_filter3 = f"(dhcp) && (wlan.addr == {self.bssid}) && (wlan.addr == {self.dut_mac_address})"
        logger().info(f"validate PS-POLL frame with PM bit set to '1'")
        packet_filter4 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {self.dut_mac_address}) ' \
                         f'and (wlan.ra == {self.bssid}))'
        logger().info(f"validate QOS data frame with more data bit set to '1'")
        packet_filter5 = f' (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {self.dut_mac_address}) ' \
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
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Sniffer validation failed for ps-poll frame with PM bit 1'
        logger().info('Validating more data bit in QOS data frames')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
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
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address)
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

def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=60)
    logger().info(f"Leave completed in {t.duration} seconds")

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
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, testcase=testcase)
    wifi_obj.join_get_ip()
    wifi_obj.powersave_ping()
    time.sleep(5)
    logger().info("Initiating BLE connect and disconnect on DUT for 5 iterations")
    for i in range(1,iter_count):
        time.sleep(2)
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(1)
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        time.sleep(2)
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
        "features":  RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
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
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, testcase=testcase)
    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)"
    wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    wifi_obj.powersave_ping()
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

import pytest
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping, get_host_ip
from utf.utils.stopwatch import Stopwatch
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
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116PowerSaveProcedureTypes
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap, RS9116BTFeatureBitMap
)
from utf.utils.thread_base import ThreadBase
import time

def logger():
    return get_logger(__name__)

class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, bssid=None, dut_mac_address=None, testcase=None, device_ip=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.utf_constants = utf_constants
        self.wifi_sniffer = wifi_sniffer
        self.bssid = bssid
        self.dut_mac_address = dut_mac_address
        self.testcase = testcase
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

    def powersave_ping(self):
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
        ping(self.device_ip, ping_count)
        time.sleep(5)

    def sniffer_validation(self):
        validation = True
        packet_filter1 = f"wlan.addr=={self.dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter2 = f"wlan.addr=={self.bssid} && wlan.fc.type_subtype == 1 ||eapol"
        packet_filter3 = f"(dhcp) && (wlan.addr == {self.bssid}) && (wlan.addr == {self.dut_mac_address})"
        logger().info(f"validate PS-POLL frame with PM bit set to '1'")
        packet_filter4 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {self.dut_mac_address}) ' \
                         f'and (wlan.ra == {self.bssid}))'
        logger().info(f"validate QOS data frame with more data bit set to '1'")
        packet_filter5 = f' (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {self.dut_mac_address}) ' \
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
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Sniffer validation failed for ps-poll frame with PM bit 1'
        logger().info('Validating more data bit in QOS data frames')
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
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
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address)
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

def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=60)
    logger().info(f"Leave completed in {t.duration} seconds")

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
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, testcase=testcase)
    wifi_obj.join_get_ip()
    wifi_obj.powersave_ping()
    time.sleep(5)
    logger().info("Initiating BLE connect and disconnect on DUT for 5 iterations")
    for i in range(1,iter_count):
        time.sleep(2)
        ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(1)
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        time.sleep(2)
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
        "features":  RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
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
    wifi_obj = WifiThread(wifi_dut, wifi_access_point, utf_constants, wifi_sniffer, testcase=testcase)
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

