import time
import pytest
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.utils.thread_base import ThreadBase
from utf.utils.logger import get_logger
from utf.utils.iperf.iperf_utils import ping
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryLevelCharacteristic
from utf.interfaces.bluetooth import BLEDeviceState
import threading
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
    RS9116Band
    )



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

    Author: Swathi pathuri
"""




# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_sniffer=None,wifi_dut=None, \
                 wifi_access_point=None,testcase=None,wifi_client=None,\
                 net_perf_client=None,protocol=None,test_type=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type

    def __print_throughput(self,iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

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

        #time.sleep(5)
        # This API Enables the DHCP in DUT
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Found device ip: {device_ip}")

        # Fetches the DUT mac address
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        #This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # # Enables the bt power save in DUT
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 100)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

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




# this thread used for wifi join
class WifiRejoinThread(ThreadBase):
    def __init__(self, wifi_sniffer=None,wifi_dut=None, \
                 wifi_access_point=None,testcase=None,wifi_client=None,\
                 net_perf_client=None,protocol=None,test_type=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.test_type = test_type

    def __print_throughput(self,iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def ApWirelessOFF_ON(self,wait_time):

        time.sleep(wait_time)
        logger().info(f"Disabling Wireless in AP")
        self.wifi_access_point.interfaces.wifi.stop_ap()
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        logger().info(f"Enabling Wireless in AP")
        self.wifi_access_point.interfaces.wifi.start_ap()

    def run_traffic_rejoin_functionality(self,device_ip,dut_mac_address):

        validation = True
        packet_filter2 = False
        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        logger().info(f"host ip :{host_ip}")

        t1 = threading.Thread(target=self.ApWirelessOFF_ON(20))
        t1.start()
        #t1.join()

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        self.net_perf_client.interfaces.net_perf.client_options["time"] = 200

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
        self.__print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

        packet_filter1 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and wlan.fc.type_subtype == ' \
                         f'0x0004 and wlan.da == ff:ff:ff:ff:ff:ff'
        packet_filter2 = f"wlan.addr=={dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"
        packet_filter3 = f"wlan.addr=={self.wifi_access_point.interfaces.wifi.bssid} && wlan.fc.type_subtype == 1 || eapol"

        packet_filter4 = f'wlan_radio.channel == {self.wifi_access_point.interfaces.wifi.channel} and ' \
                         f'wlan.da == {dut_mac_address} and wlan.ta == {self.wifi_access_point.interfaces.wifi.bssid} and ' \
                         f'wlan.fc.type_subtype == 0x0028'

        self.wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validating probe request frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find probe request frames in sniffer capture'
        logger().info(f"Validating association request frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find association request frames in sniffer capture'
        logger().info(f"Validating association response frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
            'packet_count'], 'Unable to find association response frames in sniffer capture'
        logger().info(f"Validating data packets after rejoin")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
            'packet_count'], 'Unable to find data packets after rejoin in sniffer capture'

    def run(self):

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

        # Fetches the DUT mac address
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        # This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # # Enables the bt power save in DUT
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 50)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        if self.test_type == "rejoin":
            self.run_traffic_rejoin_functionality(device_ip,dut_mac_address)






class Wireless_firmware_upgrade(ThreadBase):
    def __init__(self, wifi_sniffer,wifi_dut, wifi_access_point, wiseconnect_web,testcase):
        super().__init__()
        self.wifi_sniffer = wifi_sniffer
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wiseconnect_web = wiseconnect_web
        self.testcase = testcase

    def run(self):
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        self.wifi_dut.interfaces.wifi.start_ip()
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip: {device_ip}")
        status = ping(device_ip, 10)
        assert status is True, "DUT is not responding to ping request from third party device before store configuration"

        current_version = self.wifi_dut.interfaces.wifi.version()
        logger().info(f"Current version: {current_version}")
        self.wifi_dut.interfaces.wifi.register_http_server_callbacks(1)
        # configures the values from harness on given ip address of web page
        alert_msg = self.wiseconnect_web.interfaces.wiseconnect_ui.admin_firmware_upgrade(
            ip_address=device_ip, firmware_file_path='/app/manifest/RS9116W.2.4.1.17.rps', upgrade_wait_time=300)
        logger().info(f"upgraded message: {alert_msg}")
        self.wifi_dut.reset()
        time.sleep(90)
        self.wifi_dut.interfaces.wifi.wireless_init()
        upgraded_version = self.wifi_dut.interfaces.wifi.version()
        logger().info(f"Upgraded version: {upgraded_version}")

        self.wifi_sniffer.interfaces.capture.stop_capture()


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

            logger().info("Device is connected as a BLE slave")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


#this thread used for sta+ble as a slave
class BleThread_Scan(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        logger().info(f"{bt_dut_address}")

        # Start ble client
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        logger().info(f"advertised remote BLE device")

        # Start scanning
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address,timeout=100)
        logger().info(f"Remote device found in scan results ,BLE scanning is successful")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()


#thread for wifi scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_sniffer,wifi_dut, wifi_access_point,testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer = wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase

    def run(self):
        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        # Enables the bt power save in DUT
        logger().info("Setting DUT in wifi power save...")
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode8)

        #Enables the bt power save in DUT
        logger().info("Setting DUT in bt power save...")
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode8)

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

        logger().info(f"scan is successful with scan results: {scan_results}")

        self.wifi_sniffer.interfaces.capture.stop_capture()


class ble_gatt_client_master(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):

        # Start DUT
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_gatt_start()
        assert bt_dut_address is not None

        # Start ble client
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address,
                                                                          service_classes=[BatteryService])
        assert bt_client_address is not None

        logger().info(f"Initiating BLE scan")

        # Start scanning and connect to ble client
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
        logger().info(f"Initiating BLE scan successful")
        self.wifi_dut.interfaces.wifi.ble_stop_scanning()

        # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
        logger().info(f"Initiating BLE connection")
        self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=120,
                                             expected="RSI_BLE_CONN_UPDATE_COMPLETE_EVENT")
        logger().info(f"Initiating BLE connection successful")


        # Get the state of the dut
        state = self.wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected

        # get all profiles
        uuids = self.wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=bt_client_address)
        assert BatteryService.UUID in uuids

        # resolve battery profile
        start_handle, end_handle = self.wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=bt_client_address,
                                                                 uuid=int(BatteryService.UUID, 16))
        assert start_handle is not None
        assert end_handle is not None

        # resolve characteristics of battery profile
        uuids, write_handles, char_properties = self.wifi_dut.interfaces.wifi.ble_get_char_services_async(ble_remote_dev_address=bt_client_address,
                        start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
        assert BatteryLevelCharacteristic.UUID in uuids
        index = uuids.index(BatteryLevelCharacteristic.UUID)

        assert char_properties[index].isdigit()
        # Disconnect
        #self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address,timeout=30)
        self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
 )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_C20225(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
                                                                  net_perf_client,protocol,ble_client):
    testcase = "test_C20225"
    logger().info("testcase : TCP data transfer functionality while STA is in rejoin process")
    mode = "ble_slave"
    test_type = "rejoin"

    with WifiRejoinThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol,test_type), \
         BleThread_Connection(wifi_dut, ble_client, mode):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_C20226(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
                                                                  net_perf_client,protocol,ble_client):
    testcase = "test_C20226"
    logger().info("testcase : UDP data transfer functionality while STA is in rejoin process")
    mode = "ble_slave"
    test_type = "rejoin"

    with WifiRejoinThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol,test_type), \
         BleThread_Connection(wifi_dut, ble_client, mode):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.HTTPServer,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    "rejoin_max_retry": 0,
    "scan_interval": 6,
    "beacon_missed_count": 40,
    "first_time_retry": 0,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_C20221(wifi_sniffer,wifi_dut,wifi_access_point,ble_client,wiseconnect_web):
    testcase = "test_C20221"
    logger().info("testcase : Wireless configuration in WPA2 mode")
    mode = "ble_slave"
    with Wireless_firmware_upgrade(wifi_sniffer,wifi_dut,wifi_access_point,wiseconnect_web,testcase), \
         BleThread_Connection(wifi_dut, ble_client, mode):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    }
 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_C20199(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_C20199"
       logger().info("testcase : Verify scan functionality of DUT(STA+BLE) in standby state")
       with ScanThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase),\
              BleThread_Scan(wifi_dut, ble_client):
           time.sleep(15)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

    }
 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_C20188(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
                                                                  ble_client):
    testcase = "test_C20188"
    logger().info("testcase : Read characteristic value by UUID")
    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client), \
            ble_gatt_client_master(wifi_dut, ble_client):
        time.sleep(5)





# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
#             OpenMode | RS9116FeatureBitMap.PSKSecurity,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#
#     }
#  )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
# @pytest.mark.parametrize("protocol", [IperfConstants.UDP])
# @pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# def test_C20224(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
#                                                                   net_perf_client,protocol,ble_client):
#     testcase = "test_C20224"
#     logger().info("testcase : TCP ,UDP data transfer and reception with variable size(1-1460 bytes)")
#     mode = "ble_slave"
#     with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol,test_type="data_len"), \
#          BleThread_Connection(wifi_dut, ble_client, mode):
#         time.sleep(5)
#
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "rejoin_max_retry": 10,
#         "scan_interval": 6,
#         "beacon_missed_count": 40,
#         "first_time_retry": 0,
#     }
#  )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
# def test_C20200(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
#        testcase = "test_C20199"
#        logger().info("testcase : Verify scan functionality of DUT(STA+BLE) in standby state")
#        with ScanThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase),\
#               BleThread_Scan(wifi_dut, ble_client):
#            time.sleep(15)