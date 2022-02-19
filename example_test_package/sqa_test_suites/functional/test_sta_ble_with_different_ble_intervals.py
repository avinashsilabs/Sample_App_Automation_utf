import pytest
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from interfaces.iperf.iperf_constants import IperfConstants,IperfTrafficType
from interfaces.iperf.iperf_device_output_parser import Result
from utils.iperf.iperf_utils import print_dict
from utils.iperf.iperf_utils import ping
from interfaces.wifi import WlanError
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap,RS9116ExtTCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from utils.thread_base import ThreadBase
import time



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
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5. Verify power management bit to be enable in Null data frames and ps polls
        5. Initiate BLE advertise/scan

    Author: swathi.pathuri
"""

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_sniffer=None,wifi_dut=None, \
                 wifi_access_point=None,testcase=None,wifi_client=None,\
                 net_perf_client=None,protocol=None,http_server=None,index_path=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.net_perf_client = net_perf_client
        self.protocol = protocol
        self.wifi_client = wifi_client
        self.http_server = http_server
        self.index_path = index_path

    def __print_throughput(self,iperf_throughput: dict):
        if iperf_throughput is not None:
            print_dict("##     ", iperf_throughput)

    def run_traffic(self,device_ip):

        host_ip = self.wifi_client.interfaces.wifi.get_ip_address()
        #assert self.wifi_client.interfaces.wifi.ping(server_ip=device_ip) < 0.1

        logger().info(f"host ip :{host_ip}")

        self.net_perf_client.interfaces.net_perf.init_client(host_ip=host_ip, device_ip=device_ip, protocol=self.protocol)

        # creating results object for sharing between host and dut
        result = Result(self.net_perf_client.interfaces.net_perf.protocol)

        # open socket and start listening
        with self.wifi_dut.interfaces.wifi.start_socket_reader(
                log_file=self.net_perf_client.interfaces.net_perf.device_log_file_handle,
                result=result,
                protocol=self.net_perf_client.interfaces.net_perf.protocol,
                port=self.net_perf_client.interfaces.net_perf.client_port,
                device_ip=device_ip,
                data_len=self.net_perf_client.interfaces.net_perf.client_data_len,
                time=self.net_perf_client.interfaces.net_perf.client_timeout) as obj:
            # start iperf
            self.net_perf_client.interfaces.net_perf.start()
            logger().info("Iperf data transfer started")

            # capture device output
            self.wifi_dut.interfaces.wifi.read_from_device(obj, self.net_perf_client.interfaces.net_perf.client_timeout)

        # get and print throughput
        tp = self.net_perf_client.interfaces.net_perf.process_output(result)
        assert tp is not None
        self.__print_throughput(tp)
        logger().info(f"Iperf data transfer completed successfully")

    def run_http_download(self):

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

        # API used to get the http data
        self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)

        logger().info(f"Http download is successful")


    def run(self):

        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)
        #time.sleep(5)
        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")

        #time.sleep(5)
        # This API Enables the DHCP in DUT
        ip_config = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        device_ip = self.wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"Found device ip: {device_ip}")

        # This API Enables the wifi power save mode in DUT
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
                f'wlan.da == {dut_mac_address} and wlan.ta == {self.wifi_access_point.interfaces.wifi.bssid} and '\
                f'wlan.fc.moredata == 1 and wlan.fc.type_subtype == 0x0028'

        # Validating the ps poll frames
        packet_filter2 = f'wlan.addr == {dut_mac_address} and wlan.fc.type_subtype == 0x001a and wlan.fc.pwrmgt == 1'

        self.wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"Validating power management bit 1 in QOS data frames")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find power management bit in sniffer capture'

        logger().info(f"Validating PS Poll frames are sent from the device")
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find ps polls in sniffer capture'


        if self.net_perf_client:
            self.run_traffic(device_ip)

        if self.http_server:
            self.run_http_download()





#this thread used for sta+ble as a slave
class BleThread_Advertise(ThreadBase):
    def __init__(self, wifi_dut, ble_client, adv_int):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.adv_int = int(adv_int/0.625)

    def run(self):
        # Set up DUT for BLE advertising
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        time.sleep(5)

        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=self.adv_int, \
                                                            ble_adv_int_max=self.adv_int,timeout=30)

        logger().info(f"Started advertising DUT")

        # Begin Scanning for BLE devices
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

        logger().info(f"Started scan from remote BLE device")

        logger().info("\n***********{}**********\n".format(bt_client_address))


        for i in range(0,10):

            time.sleep(5)

            if self.adv_int > 1000:

                time.sleep(10)

            # See that we found our device

            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            logger().info("\n***scan results:{}**********\n".format(found_devices))

            if self.wifi_dut.interfaces.wifi.ble_address in found_devices:
                break

        self.ble_client.interfaces.bluetooth.stop_scanning()
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
        logger().info(f"*****logic analyzer validation is pending*******")



#this thread used for sta+ble as a slave
class BleThread_Scan(ThreadBase):
    def __init__(self, wifi_dut, ble_client,ble_scan_interval,ble_scan_window):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_scan_interval=int(ble_scan_interval/0.625)
        self.ble_scan_window=int(ble_scan_window/0.625)


    def run(self):
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None

        logger().info(f"{bt_dut_address}")

        # Start ble client
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(1)

        logger().info(f"advertised remote BLE device")

        # Start scanning
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, \
                                                             ble_scan_interval=self.ble_scan_interval, \
                                                             ble_scan_window=self.ble_scan_window, timeout=1500)

        logger().info(f"Remote device found in scan results ,BLE scanning is successful")

        logger().info(f"*****logic analyzer validation is pending*******")
        #self.wifi_dut.interfaces.wifi.ble_stop_scanning()



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
            timeout = 120
            logger().info(f"Initiating connection this can take upto {timeout} seconds....")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)
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

            # self.ble_client.interfaces.bluetooth.connect(bt_dut_address,min_conn_interval=int(50/0.625),
            #     max_conn_interval= int(50/0.625), conn_latency  = int(2/0.625), supervision_timeout = int(16000/0.625))
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address, min_conn_interval=0x28,
                                                         max_conn_interval=0x28, conn_latency=2,
                                                         supervision_timeout=16000)


            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

            logger().info(f"*****BLE sniffer validation is pending*******")




#thread for wifi scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_sniffer,wifi_dut, wifi_access_point,testcase):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_sniffer =wifi_sniffer
        self.wifi_access_point = wifi_access_point
        self.testcase = testcase


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

        self.wifi_sniffer.interfaces.capture.stop_capture()







@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,

    }
 )


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_advertising_interval_of_20ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_Wifi_scan_with_BLE_advertising_interval_of_20ms"
       with ScanThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase),BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
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

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_AP_connection_with_BLE_advertising_interval_of_20ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
    testcase = "test_AP_connection_with_BLE_advertising_interval_of_20ms"
    with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)

#


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

    },
 )

@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
def test_Wifi_Data_transfer_with_BLE_advertising_interval_of_20ms(wifi_sniffer,wifi_dut,\
                                                                       wifi_access_point,wifi_client,\
                                                                  net_perf_client,ble_client,protocol):
    testcase = "test_Wifi_Data_transfer_with_BLE_advertising_interval_of_20ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol),\
            BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)

# #
#
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

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_advertising_interval_of_10240ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_Wifi_scan_with_BLE_advertising_interval_of_10240ms"
       with ScanThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase),\
               BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)

#

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_AP_connection_with_BLE_advertising_interval_of_10240ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
    testcase = "test_AP_connection_with_BLE_advertising_interval_of_10240ms"
    with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), \
            BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)

#
#


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

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
def test_Wifi_Data_transfer_with_BLE_advertising_interval_of_10240ms(wifi_sniffer,wifi_dut,\
                                                                       wifi_access_point,wifi_client,\
                                                                  net_perf_client,protocol,ble_client):
    testcase = "test_Wifi_Data_transfer_with_BLE_advertising_interval_of_10240ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol), \
         BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,

        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)


@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_Wifi_http_download_BLE_advertising_interval_of_20ms(wifi_sniffer,http_server,wifi_dut, wifi_access_point,\
                                                             ble_client,index_path):
    testcase = "test_Wifi_http_download_BLE_advertising_interval_of_20ms"
    with WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase,http_server = http_server, index_path=index_path),\
         BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)

@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.config('wifi_access_point',wifi ={"security": 'WPA2'})
def test_Wifi_http_download_BLE_advertising_interval_of_10240ms(wifi_sniffer,http_server,wifi_dut, wifi_access_point,\
                                                             ble_client,index_path):

    testcase = "test_Wifi_http_download_BLE_advertising_interval_of_10240ms"
    with WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase,http_server = http_server, index_path=index_path), \
            BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
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

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_Scan_interval_of_10240ms_scan_window_5000ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_Wifi_scan_with_BLE_Scan_interval_of_10240ms_scan_window_5000ms"
       with ScanThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase),\
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=5000):
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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_AP_connection_with_BLE_Scan_interval_of_10240ms_scan_window_5000ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_AP_connection_with_BLE_Scan_interval_of_10240ms_scan_window_5000ms"
       with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), \
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=5000):
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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
def test_Wifi_Data_transfer_with_BLE_Scan_interval_of_10240ms_scan_winodw_5000ms(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
                                                                  net_perf_client,protocol,ble_client):

    testcase = "test_Wifi_Data_transfer_with_BLE_Scan_interval_of_10240ms_scan_winodw_5000ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol), \
         BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=5000):
        time.sleep(15)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)

@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_http_download_with_BLE_scan_interval_of_10240ms_and_scan_window_of_5000ms(wifi_sniffer,http_server,\
                                                wifi_dut, wifi_access_point,ble_client,index_path):
       testcase = "test_Wifi_http_download_with_BLE_scan_interval_of_10240ms_and_scan_window_of_50000ms"
       with WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase,http_server = http_server, index_path=index_path), \
            BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=5000):
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
#
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_Scan_interval_of_5ms_scan_window_2point5ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_Wifi_scan_with_BLE_Scan_interval_of_5ms_scan_window_2point5ms"
       with ScanThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase),\
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5,ble_scan_window=2.5):
           time.sleep(15)
#

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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_AP_connection_with_BLE_Scan_interval_of_5ms_scan_window_2point5ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_AP_connection_with_BLE_Scan_interval_of_5ms_scan_window_2point5ms"
       with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), \
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5,ble_scan_window=2.5):
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
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.CLIENT_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config("wifi_client", wifi={"interface": "eth0"})
def test_Wifi_Data_transfer_with_BLE_Scan_interval_of_5ms_scan_winodw_2point5ms(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
                                                                  net_perf_client,protocol,ble_client):

    testcase = "test_Wifi_Data_transfer_with_BLE_Scan_interval_of_5ms_scan_winodw_2point5ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, net_perf_client,protocol), \
         BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5,ble_scan_window=2.5):
        time.sleep(15)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)

@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_http_download_with_BLE_scan_interval_of_5ms_and_scan_window_of_2point5ms(wifi_sniffer,http_server,\
                                                wifi_dut, wifi_access_point,ble_client,index_path):
       testcase = "test_Wifi_http_download_with_BLE_scan_interval_of_5ms_and_scan_window_of_2point5ms"
       with WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase,http_server = http_server, index_path=index_path), \
            BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=5,ble_scan_window=2.5):
            time.sleep(15)
