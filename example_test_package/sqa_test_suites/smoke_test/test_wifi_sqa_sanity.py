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
    RS9116PowerSaveProcedureTypes,
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

ping_count = 60


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
        logger().info(f"Remote device ip :{host_ip}")

        logger().info("starting the server from Remote device")

        # starting iperf
        self.net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=self.protocol)
        self.net_perf_client.interfaces.net_perf.start()
        #self.net_perf_client.interfaces.net_perf.client_options["time"] = 50

        logger().info("sending data from DUT")
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
        assert tp is not None,"Throughput not found"
        logger().info("data transfer is successful")


    def run(self):

        validation = True

        logger().info(f"starting the sniffer in channel {self.wifi_access_point.interfaces.wifi.channel}")

        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{self.testcase}_beacons")

        time.sleep(10)

        ##validating beacons from AP

        packet_filter1 = f'(wlan.fc.type_subtype == 0x0008) and (wlan.addr == {self.wifi_access_point.interfaces.wifi.bssid})'

        logger().info("stopping the sniffer")

        self.wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating beacons in sniffer with filter : {}".format(packet_filter1))
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'],"Beacons not found in sniffer capture"

        for count in range(0,self.iteration):

            logger().info("starting the sniffer again")

            self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

           #bles the scan in dut on channel
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0,ssid=None)

            logger().info(f"scan results : {scan_results}")
            assert (len(scan_results) >= 1),"Scan failed"

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

            ap_bssid = self.wifi_access_point.interfaces.wifi.bssid
            logger().info(f"ap_bssid : {ap_bssid}")

            logger().info("Initiating power save")
            logger().info("enabling wifi power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                RS9116PowerSaveProcedureTypes.FastPowerSave)

            logger().info("enabling bt power save mode in DUT......")
            self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                   RS9116PowerSaveProcedureTypes.FastPowerSave)
            time.sleep(5)

            # Initiate ping from third party wifi-client to DUT
            status = ping(device_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")

            if self.test_type == "iperf":
                logger().info("Running data transfer")
                self.run_traffic(device_ip)

            logger().info("disconnecting to ap.....")
            self.wifi_dut.interfaces.wifi.leave()

            logger().info("stopping the sniffer capture")
            self.wifi_sniffer.interfaces.capture.stop_capture()
            # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
            packet_filter2 = f'!(wlan.fc.type_subtype == 0x0008) and  ' \
                 f'((wlan.fc.type_subtype == 0x0000) or (wlan.fc.type_subtype==0x0001) ) or eapol or ' \
                 f'(wlan.fc.type_subtype == 0x000b) or (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

            assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)
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
                logger().info(f"getting scan results ,Retrying for multiple times")
        assert (len(scan_results) >= 1)

        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")

        # This API Enables the DHCP in DUT
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Found device ip: {device_ip}")

        logger().info("enabling wifi power save mode in DUT......")
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("enabling bt power save mode in DUT......")
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        # Fetches the DUT mac address
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        packet_filter1 = f'wlan.da == {dut_mac_address} and wlan.ta == {self.wifi_access_point.interfaces.wifi.bssid} and ' \
                         f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        logger().info("stopping the capture")

        self.wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validating more data bit in QOS data frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find more data bit in QOS data frames in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device with power management bit")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'

        logger().info("disconnecting to ap.....")
        self.wifi_dut.interfaces.wifi.leave()

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
            assert bt_dut_address is not None,f"Unable to fetch MAC address from DUT"
            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None,f"Unable to fetch MAC address from Remote device"
            time.sleep(1)

            logger().info("initiating BLE scan from DUT")
            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=20)
            # Sometimes Connection is not triggered for a long time. Is this a bug on DUT, or issue with Raspi?
            logger().info(f"Initiating connection.")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=120)

            logger().info("Device is connected as a BLE master")

            time.sleep(60)

            logger.info("Initiating disconnect from DUT")
            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

            logger.info("Initiating stop scanning")
            self.wifi_dut.interfaces.wifi.ble_stop_scanning()

            logger.info("Initiating stop advertising")
            self.ble_client.interfaces.bluetooth.stop_advertising()

        if (self.mode == "ble_slave"):
            # Set up DUT for BLE advertising
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None,f"Unable to fetch MAC address from DUT"

            logger().info("Advertising the DUT")
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            logger().info("Initiating scan from BLE client")
            # Begin Scanning for BLE devices
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None,"Unable to fetch MAC address from Remote device"

            logger().info(f"Remote BT device address : {bt_client_address}")
            # See that we found our device
            found_devices = ""
            for i in range(0, 5):
                time.sleep(5)
                # See that we found our device
                found_devices = self.ble_client.interfaces.bluetooth.get_devices()
                logger().info("\n***scan results:{}**********\n".format(found_devices))
                if self.wifi_dut.interfaces.wifi.ble_address in found_devices:
                    logger().info("remote device is able to scan the DUT successfully ")
                    break
            logger().info(f"Stop Scanning for REMOTE devices")
            self.ble_client.interfaces.bluetooth.stop_scanning()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"
            logger().info("Initiating connection from DUT")

            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            logger().info("Device is connected as a BLE slave")

            time.sleep(60)

            logger().info("Initiating disconnect from BLE client")
            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)



@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
def test_join_WORLD_2_4_C34788(wifi_access_point, wifi_dut, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_WORLD_2_4_C34788"
    test_type = "iperf"

    logger().info("DUT set to Region -. World domain")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                        net_perf_client, protocol,test_type,iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
def test_join_EU_2_4_C34786(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_2_4_C34786"
    test_type = "iperf"
    logger().info("Setting the DUT to Region Europe")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
def test_join_US_2_4_C34785(wifi_access_point, wifi_dut, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_2_4_C34785"
    test_type = "iperf"

    logger().info("Setting the DUT to Region US")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
def test_join_US_5Ghz_C34789(wifi_access_point, wifi_dut, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_5Ghz_C34789"
    test_type = "iperf"
    logger().info("Setting the DUT to Region US")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
def test_join_EU_5Ghz_C34790(wifi_access_point, wifi_dut, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_5Ghz_C34790"
    test_type = "iperf"

    logger().info("Setting the DUT to Region Europe")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
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
def test_join_WORLD_5Ghz_C34792(wifi_access_point, wifi_dut, net_perf_client,  wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_WORLD_5Ghz_C34792"
    test_type = "iperf"

    logger().info("Setting the DUT to Region World")
    wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                 net_perf_client, protocol, test_type, iteration=1)
    wifi_thread.start()
    wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "band": 2,
        "region": 1,
        "region_code": 1,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"region": "US","channel": 6})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_US_dual_band_C34793(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_US_dual_band_C34793"
    test_type = "iperf"

    logger().info("Setting the DUT to Region US")
    dual_channel = [6, 36]
    for channel in dual_channel:
        testcase = f"test_join_US_dual_band_{channel}_"
        wifi_access_point.interfaces.wifi.config['channel'] = channel
        # Set the region value in AP side
        wifi_access_point.interfaces.wifi.config['region'] = 'US'
        # Set the region value in DUT side

        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(10)
        wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                     net_perf_client, protocol, test_type, iteration=1)
        wifi_thread.start()
        wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "band": 2,
        "region": 1,
        "region_code": 2,
        "module_type": 1,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"region": "Europe","channel": 12})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_EU_dual_band_C34794(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_EU_dual_band_C34794"
    test_type = "iperf"
    logger().info("Setting the DUT to Region Europe")
    dual_channel = [12, 48]
    for channel in dual_channel:
        testcase = f"test_join_EU_dual_band_{channel}_"
        wifi_access_point.interfaces.wifi.config['channel'] = channel
        # Set the region value in AP side
        wifi_access_point.interfaces.wifi.config['region'] = 'Europe'
        # Set the region value in DUT side

        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(10)
        wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                     net_perf_client, protocol, test_type, iteration=1)
        wifi_thread.start()
        wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",

    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "band": 2,
        "region": 1,
        "region_code": 4,
        "module_type": 1,
    },
)

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.config("wifi_access_point", wifi={"region": "Asia","channel": 1})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_join_WORLD_dual_band_C34796(wifi_access_point, wifi_dut, net_perf_client, wifi_sniffer, wifi_client, protocol):
    testcase = "test_join_WORLD_dual_band_C34796"
    test_type = "iperf"
    logger().info("Setting the DUT to Region World mode")
    dual_channel = [1, 44]
    for channel in dual_channel:
        testcase = f"test_join_WORLD_dual_band_{channel}_"
        wifi_access_point.interfaces.wifi.config['channel'] = channel
        # Set the region value in AP side
        wifi_access_point.interfaces.wifi.config['region'] = 'Asia'
        # Set the region value in DUT side

        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(10)
        wifi_thread = WifiJoinThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase, wifi_client,\
                                     net_perf_client, protocol, test_type, iteration=1)
        wifi_thread.start()
        wifi_thread.wait_for_exit()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
    }
)
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2',"passphrase": '123456789'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Connectivity_with_WPA2_security_AP_C34757(wifi_access_point, wifi_dut,  wifi_sniffer):
    with TimeMeasurer() as t:
        validation = True

        logger().info(" ====== configuring the sniffer with access point channel ====== ")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        logger().info(" ====== start capturing with Sniffer by giving the test case name as filename ====== ")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Connectivity_with_WPA2_security_AP')

        logger().info("scan for the ap's.....")
        ap_mac = wifi_dut.interfaces.wifi.scan(ssid=None,channel=0)

        logger().info("connecting to access point.....")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        logger().info("enabling dhcp in DUT.......")
        result = wifi_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

        logger().info("enabling wifi power save mode in DUT......")
        wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                            RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("enabling bt power save mode in DUT......")
        wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                               RS9116PowerSaveProcedureTypes.FastPowerSave)

        logger().info("fetching dut mac address....")
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        logger().info(f"dut_mac_address : {dut_mac_address}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f"AP_mac_address : {ap_bssid}")

        ## Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
        packet_filter1 = f'!(wlan.fc.type_subtype == 0x0008) and  ' \
                 f'((wlan.fc.type_subtype == 0x0000) or (wlan.fc.type_subtype==0x0001) ) or eapol or ' \
                 f'(wlan.fc.type_subtype == 0x000b) or (wlan.addr == {ap_bssid}) || (wlan.addr == {dut_mac_address})'

        # Validating the power management bit
        packet_filter3 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, ping_count)
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

        logger().info("disconnecting to ap.....")
        wifi_dut.interfaces.wifi.leave()
    logger().info(f"Associated and ping in {t.duration} seconds")



@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
    },
)

@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '123456789'})
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_rejoin_functionality_C34758(wifi_sniffer, wifi_dut, wifi_access_point):

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


    logger().info("Initiating power save")

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device"
    logger().info(f"ping is successful")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    # Validate Probe req(Broadcast/Unicast)

    packet_filter1 = f'wlan.sa == {mac_address}  and ' \
                     f'wlan.fc.type_subtype == 0x0004 and (wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate Probe req(Broadcast/Unicast), authentication ,association, eapol
    packet_filter3 = f'!(wlan.fc.type_subtype == 0x0008) and  ' \
                     f'((wlan.fc.type_subtype == 0x0000) or (wlan.fc.type_subtype==0x0001) ) or eapol or ' \
                     f'(wlan.fc.type_subtype == 0x000b) or (wlan.addr == {ap_bssid}) || (wlan.addr == {mac_address})'


    logger().info("Starting the capture")
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broadcast_prob_req')
    time.sleep(2)
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(10)
    logger().info("Stoping the capture")
    wifi_sniffer.interfaces.capture.stop_capture()
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count']
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_procedure')
    wifi_access_point.interfaces.wifi.start_ap()
    time.sleep(60)
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    time.sleep(5)
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3, packet_filter2)[
        'packet_count']

    # Initiate ping from third party wifi-client to DUT
    status = ping(device_ip, ping_count)
    assert status is True, "DUT is not responding to ping request from third party device after rejoin"
    logger().info(f"ping is successful after rejoin")

    logger().info("disconnecting to ap.....")
    wifi_dut.interfaces.wifi.leave()




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable","disassociated", "ble_disconnect"])
def test_connectivity_and_ping_in_STA_BLE_coex_mode_C34778(wifi_access_point, wifi_dut,  ble_client,wifi_sniffer):
       testcase = "test_connectivity_and_ping_in_STA_BLE_coex_mode_C34778"
       logger().info(f"testcase : {testcase}")
       mode = "ble_slave"

       wifi_thread = WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase)
       ble_thread = BleThread_Connection(wifi_dut, ble_client, mode)
       wifi_thread.start()
       time.sleep(5)
       ble_thread.start()
       wifi_thread.wait_for_exit()
       ble_thread.wait_for_exit()



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
 )

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_ble_connect_as_slave_C34770(wifi_dut, ble_client):
    # Set up DUT for BLE advertising
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None, "DUT BT Address not found"
    logger().info(f"BT Address of DUT is {bt_dut_address}")
    logger().info(f"Start Advertising on DUT")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    # Begin Scanning for BLE devices
    logger().info(f"Begin Scanning for BLE devices")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, "BT REMOTE devices not found"
    logger().info(f"BT Address of BT CLIENT DEVICE is {bt_client_address}")
    time.sleep(10)
    found_devices = ""
    for i in range(0, 5):
        time.sleep(5)
        # See that we found our device
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info("\n***scan results:{}**********\n".format(found_devices))
        if wifi_dut.interfaces.wifi.ble_address in found_devices:
            logger().info("remote device is able to scan the DUT successfully ")
            break
    logger().info(f"Stop Scanning for REMOTE devices")
    ble_client.interfaces.bluetooth.stop_scanning()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices, "DUT not found in scan results"
    logger().info(f"Connecting DUT to REMOTE device")
    ble_client.interfaces.bluetooth.connect(wifi_dut.interfaces.wifi.ble_address)
    time.sleep(60)
    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    logger().info(f"Getting device state : {state} ")
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in slave mode"
    logger().info(f"Dut is in connected state {state_int}")
    logger().info(f"DUT has connected to BLE CLIENT and is in Slave Mode")
    logger().info(f"Disconnecting the REMOTE device")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    }
 )
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated","ble_disconnect"])
def test_ble_connect_as_master_C34771(wifi_dut, ble_client):
    # Start DUT
    bt_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert bt_dut_address is not None, "DUT BT Address not found"
    logger().info(f"BT Address of DUT is {bt_dut_address}")
    # Start ble client
    logger().info(f"Starting Advertisement on BT CLIENT DEVICE")
    #bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_adv_with_hci_tool(
        bt_dut_address=bt_dut_address,
        hci_adv_params="0x40 0x00 "  # Advertising_Interval_Min
                       "0x40 0x00 "  # Advertising_Interval_Max
                       "0x00 "  # Advertising_Type 0x00-ADV_IND, 1-ADV_DIRECT_IND, 2-ADV_SCAN_IND, 3-ADV_NONCONN_IND
                       "0x00 "  # Own_Address_Type
                       "0x00 "  # Peer_Address_Type
                       "0x00 0x00 0x00 0x00 0x00 0x00 "  # Peer_Address
                       "0x07 "  # Advertising_Channel_Map
                       "0x00"  # Advertising_Filter_Policy
        , scan_resp_name_params="0x0f 0x0e 0x09 0x75 0x74 0x66 0x5f 0x77 0x69 "
                                "0x66 0x69 0x5f 0x74 0x65 0x73 " \
                                "0x74 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 "
                                "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"
    )
    assert bt_client_address is not None,"BT REMOTE DEVICE not found"
    logger().info(f"BT Address of BT CLIENT DEVICE is {bt_client_address}")
    # Start scanning and connect to ble client
    logger().info(f"Start scanning on DUT and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=60)
    logger().info(f"Start scanning on DUT and connect to ble client")


    logger().info(f"Initiating connection.")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, expected="RSI_BLE_CONN_EVENT",\
                                         timeout=120)

    # Get the state of the dut
    logger().info("enabling wifi power save mode in DUT......")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info("enabling bt power save mode in DUT......")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    time.sleep(60)

    state = wifi_dut.interfaces.wifi.ble_get_device_state()

    logger().info(f"Getting device state : {state} ")
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "DUT is unable to connect in master mode"

    logger().info(f"Dut is in connected state {state_int}")
    logger().info(f"DUT has connected to BLE CLIENT and is in Master Mode")

    # Disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

    logger().info("remote BLE device has been disconnected")


