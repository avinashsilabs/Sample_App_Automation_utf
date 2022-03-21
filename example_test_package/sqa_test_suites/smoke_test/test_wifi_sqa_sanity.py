import time
import pytest
import re

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
    )
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import get_host_ip
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
from utf.utils.logger import get_logger
import string
import random
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.iperf.iperf_device_output_parser import Result
from utf.interfaces.bluetooth import BTSocketRole
from utf.interfaces.bluetooth import BLEDeviceState
from utf_wiseconnect.devices.rs911x import RS9116OperatingMode, RS9116Band


def logger():
    return get_logger(__name__)



# this thread used for wifi join
class WifiJoinThread(ThreadBase):
    def __init__(self, wifi_sniffer=None,wifi_dut=None, \
                 wifi_access_point=None,testcase=None,wifi_client=None,\
                 net_perf_client=None,protocol=None,test_type=False,iteration=1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type
        self.iteration = iteration

    def run_traffic(self,device_ip):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip :{host_ip}")

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        #self.net_perf_client.interfaces.net_perf.client_options["time"] = 50

        # open socket and send traffic
        self.wifi_dut.interfaces.wifi.send_traffic_from_device(
            host_ip,
            device_ip,
            self.net_perf_client.interfaces.net_perf.server_port,
            self.net_perf_client.interfaces.net_perf.protocol,
            self.net_perf_client.interfaces.net_perf.client_options,
        )

        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output()
        assert tp is not None
        logger().info("data transfer is successful")


    def run(self):

        validation = True

        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        time.sleep(10)

        for count in range(0,self.iteration):

            for i in range(0,3):
                try:
                    #enables the scan in dut on channel
                    scan_results = self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel,\
                                                                      ssid=self.wifi_access_point.interfaces.wifi.ssid)
                    logger().info(f"scan results : {scan_results}")
                    if len(scan_results):
                        break
                except:
                    # enables the scan in dut on channel
                    scan_results = self.wifi_dut.interfaces.wifi.scan(
                        channel=self.wifi_access_point.interfaces.wifi.channel, \
                        ssid=self.wifi_access_point.interfaces.wifi.ssid)
                    logger().info(f"scan results : {scan_results}")
                    if len(scan_results):
                        break
            assert (len(scan_results) >= 1)
            # Join Wi-Fi Access Point
            self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
            logger().info(f"Successfully connected to AP")
            # This API Enables the DHCP in DUT
            ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
            device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
            logger().info(f"Found device ip: {device_ip}")

            # Fetches the DUT mac address
            dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"Device mac address: {dut_mac_address}")

            # This API Enables the wifi power save mode in DUT
            self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

            # # Enables the bt power save in DUT
            self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
            time.sleep(5)

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, 10)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")

            if self.test_type == "iperf":
                self.run_traffic(device_ip)

            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

        self.wifi_sniffer.interfaces.capture.stop_capture()
        packet_filter1 = f"wlan.fc.type_subtype==1 and "\
                         f"wlan.ht.info.primarychannel=={self.wifi_access_point.interfaces.wifi.channel} "\
                         f"and wlan.da=={dut_mac_address}"
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)
        logger().info("sniffer validation is successful")



# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_sniffer=None,wifi_dut=None, \
                 wifi_access_point=None,testcase=None,bssid=False,wifi_client=None,\
                 net_perf_client=None,protocol=None,test_type=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.bssid = bssid
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type


    def run(self):

        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        for i in range(0,3):
            try:
                #enables the scan in dut on channel
                scan_results = self.wifi_dut.interfaces.wifi.scan(channel=self.wifi_access_point.interfaces.wifi.channel, ssid=None)
                logger().info(f"scan results : {scan_results}")
                if len(scan_results):
                    break
            except:
                # enables the scan in dut on channel
                scan_results = self.wifi_dut.interfaces.wifi.scan(
                    channel=self.wifi_access_point.interfaces.wifi.channel, ssid=None)
                logger().info(f"scan results : {scan_results}")
                if len(scan_results):
                    break
        assert (len(scan_results) >= 1)

        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")

        # This API Enables the DHCP in DUT
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Found device ip: {device_ip}")

        #This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # # Enables the bt power save in DUT
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 50)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        # Fetches the DUT mac address
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        packet_filter1 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and wlan.ta == {self.wifi_access_point.interfaces.wifi.bssid} and ' \
                         f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        self.wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validating more data bit in QOS data frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find more data bit in QOS data frames in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

# this thread used for sta+ble as a slave
class BleThread_Connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        if (self.mode == "ble_master"):
            # Start DUT
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(1)
            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=20)
            # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
            logger().info(f"Initiating connection.")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=120)

            time.sleep(50)
            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if (self.mode == "ble_slave"):
            # Set up DUT for BLE advertising
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(5)
            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices

            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)

            time.sleep(50)

            logger().info("Device is connected as a BLE slave")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
)
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
def test_Connectivity_with_WPA2_Security_AP_C19707(wifi_dut, wifi_access_point, wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_WPA2_Security_AP_C19707')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None)
        ap_bssid = str(ap_mac[0]).split(' ')[11].strip(')')
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(2)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(2)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and (wlan.tag.number == 45 ) or ' \
                         f'(wlan.fc.type_subtype == 0x0000) or (wlan.ds.current_channel == 11) or eapol or ' \
                         f'(wlan.fc.type_subtype == 0x000b)'

        # Validating the power management bit
        packet_filter3 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # Validate dhcp
        packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} or dhcp'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 20)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating Probe req(Broadcast/Unicast), authentication ,association, eapol")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find Probe req(Broadcast/Unicast), authentication ,association, eapol packet ' \
                             'in sniffer'

        logger().info(" Validate power management bit 1")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find power management bit 1 in sniffer '

        logger().info(" Validate dhcp")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find dhcp in sniffer '
    logger().info(f"Associated and ping in {t.duration} seconds")


@pytest.mark.skip()
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])

@pytest.mark.config(
    "wifi_dut",

    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
    },
)
def test_rejoin(wifi_sniffer, wifi_access_point, wifi_dut):

    validation = True
    packet_filter2 = False
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

    time.sleep(2)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # This API Enables the DHCP in DUT
    ip_config = wifi_dut.interfaces.wifi.start_ip(timeout=30)
    device_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"Found device ip: {device_ip}")

    # Fetches the DUT mac address
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    # This API Enables the wifi power save mode in DUT
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # # Enables the bt power save in DUT
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    time.sleep(5)

    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, 10)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")

    packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and ' \
                     f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff)'
    packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                     f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff '

    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_unicast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(10)
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    wifi_access_point.interfaces.wifi.start_ap()
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(60)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
 )
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable","disassociated"])
def test_connectivity_and_ping_in_STA_BLE_coex_mode(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_connectivity_and_ping_in_STA_BLE_coex_mode"
       logger().info(f"testcase : {testcase}")
       mode = "ble_slave"

       with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase),\
            BleThread_Connection(wifi_dut, ble_client, mode):
           time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_connect_T3275(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None, "DUT BT Address not found"
    logger().info(f"BT Address of DUT is {bt_dut_address}")
    logger().info(f"Start Advertising on DUT")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Begin Scanning for BLE devices
    logger().info(f"Begin Scanning for BLE devices")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, " BT REMOTE devices not found"
    logger().info(f"BT Address of BT CLIENT DEVICE is {bt_client_address}")
    time.sleep(5)
    logger().info(f"Stop Scanning for REMOTE devices after 5 seconds")
    ble_client.interfaces.bluetooth.stop_scanning()

    # See that we found our device
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )
    logger().info(f"Connecting DUT to REMOTE device")
    ble_client.interfaces.bluetooth.connect(wifi_dut.interfaces.wifi.ble_address)

    time.sleep(50)

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in slave mode"
    logger().info(f"DUT has connected to BLE CLIENT and is in Slave Mode")

    logger().info(f"Disconnecting the REMOTE device")
    ble_client.interfaces.bluetooth.disconnect(wifi_dut.interfaces.wifi.ble_address)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        }
    )
@pytest.mark.skip()
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_master_connection_testcase33(wifi_dut, ble_client):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None, "DUT BT Address not found"
    logger().info(f"BT Address of DUT is {bt_dut_address}")
    # Start ble client
    logger().info(f"Starting Advertisement on BT CLIENT DEVICE")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None,"BT REMOTE DEVICE not found"
    logger().info(f"BT Address of BT CLIENT DEVICE is {bt_client_address}")
    # Start scanning and connect to ble client
    logger().info(f"Start scanning on DUT and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=120)
    logger().info(f"Start scanning on DUT and connect to ble client")
    # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
    logger().info(f"Initiating connection.")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address,expected="RSI_BLE_CONN_EVENT", timeout=120)
    # Get the state of the dut
    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(2)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(2)

    time.sleep(50)

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in master mode"
    logger().info(f"DUT has connected to BLE CLIENT and is in Master Mode")
    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'Asia'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_join_ASIA_2_4(wifi_dut,wifi_access_point, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_ASIA_2_4"
    test_type = "iperf"

    logger().info("Setting the DUT to Region World domain")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)

    with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                        net_perf_client, protocol,test_type,iteration=1):

        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 12, "region": 'Europe'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_EU_2_4(wifi_dut, wifi_access_point, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_2_4"
    test_type = "iperf"

    logger().info("Setting the DUT to Region Europe")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)

    with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                        net_perf_client, protocol, test_type, iteration=1):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 0,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 11, "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_US_2_4(wifi_dut, wifi_access_point, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_2_4"
    test_type = "iperf"

    logger().info("Setting the DUT to Region US")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)

    with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                        net_perf_client, protocol, test_type, iteration=1):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,

        "band": 1,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 36, "region": 'US'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_US_5Ghz(wifi_dut, wifi_access_point, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_5Ghz"
    test_type = "iperf"

    logger().info("Setting the DUT to Region US")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)

    with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                        net_perf_client, protocol, test_type, iteration=1):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 1,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 48, "region": 'Europe'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_EU_5Ghz(wifi_dut, wifi_access_point, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_5Ghz"
    test_type = "iperf"

    logger().info("Setting the DUT to Region Europe")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)

    with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                        net_perf_client, protocol, test_type, iteration=1):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 1,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"channel": 44, "region": 'Asia'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_ASIA_5Ghz(wifi_dut, wifi_access_point, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_ASIA_5Ghz"
    test_type = "iperf"

    logger().info("Setting the DUT to Region World")
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=4, module_type=1)

    with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                        net_perf_client, protocol, test_type, iteration=1):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_US_dual_band(wifi_dut, wifi_access_point, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_dual_band"
    test_type = "iperf"
    dual_channel = [6, 36]
    for channel in dual_channel:
        testcase = f"test_join_US_dual_band_{channel}_"
        wifi_access_point.interfaces.wifi.config['channel'] = channel
        # Set the region value in AP side
        wifi_access_point.interfaces.wifi.config['region'] = 'US'
        # Set the region value in DUT side

        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(10)

        logger().info("Setting the DUT to Region US")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=1, module_type=1)

        with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                            net_perf_client, protocol, test_type, iteration=1):
            time.sleep(5)




@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 2,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_EU_dual_band(wifi_dut, wifi_access_point, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_dual_band"
    test_type = "iperf"
    dual_channel = [12, 48]
    for channel in dual_channel:
        testcase = f"test_join_EU_dual_band_{channel}_"
        wifi_access_point.interfaces.wifi.config['channel'] = channel
        # Set the region value in AP side
        wifi_access_point.interfaces.wifi.config['region'] = 'Europe'
        # Set the region value in DUT side

        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(10)

        logger().info("Setting the DUT to Region Europe")
        wifi_dut.interfaces.wifi.set_region(region=1, region_code=2, module_type=1)

        with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                            net_perf_client, protocol, test_type, iteration=1):
            time.sleep(5)




@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "band": 2,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"region": 'Asia'})
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_ASIA_dual_band(wifi_dut, wifi_access_point, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_ASIA_dual_band"
    test_type = "iperf"
    dual_channel = [1, 44]
    for channel in dual_channel:
        testcase = f"test_join_ASIA_dual_band_{channel}_"
        wifi_access_point.interfaces.wifi.config['channel'] = channel
        # Set the region value in AP side
        wifi_access_point.interfaces.wifi.config['region'] = 'Asia'
        # Set the region value in DUT side

        wifi_access_point.interfaces.wifi.start_ap()

        logger().info("Setting the DUT to Region World mode")
        wifi_dut.interfaces.wifi.set_region(region=1,region_code=4,module_type=1)


        time.sleep(10)
        with WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client, \
                            net_perf_client, protocol, test_type, iteration=1):
            time.sleep(5)






