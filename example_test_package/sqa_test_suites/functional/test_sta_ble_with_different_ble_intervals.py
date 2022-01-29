import pytest
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from interfaces.iperf.fixtures import IPerfFixture, iperf
from utils.iperf.Iperf_constants import IperfConstants
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

    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. Join the access point and enable the dhcp
        3. Enable the wlan and bt power save mode in dut after the connection
        4. Initiate ping from the dut
        5.initiate BLE advertise/scan

    Author: swathi.pathuri
"""

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_sniffer = None,wifi_dut=None, \
                 wifi_access_point=None,testcase=None,wifi_client=None,\
                 run_iperf=None,http_server=None,index_path=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_sniffer = wifi_sniffer
        self.testcase = testcase
        self.run_iperf = run_iperf
        self.wifi_client = wifi_client
        self.http_server = http_server
        self.index_path = index_path

    def run_traffic(self):

        iperf = IPerfFixture(
            'test1',
            self.run_iperf,
            self.wifi_access_point,
            self.wifi_dut,
            self.wifi_client,
        )
        time.sleep(5)
        iperf.run()
        logger().info("this is IPerf")

    def run_http_download(self):

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

        # API used to get the http data
        self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)

        logger().info(f"Http download is success")


    def run(self):
        validation = True
        packet_filter2 = False
        logger().info("configuring the Sniffer with the channel")
        self.wifi_sniffer.interfaces.capture.configure_interface(channel=self.wifi_access_point.interfaces.wifi.channel)

        logger().info("start capturing with Sniffer by giving the test case name as filename")
        self.wifi_sniffer.interfaces.capture.start_capture(capture_file=self.testcase)

        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")

        time.sleep(5)
        # This API Enables the DHCP in DUT
        result = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        assert isinstance(
            result,self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"
        device_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
        logger().info(f"Found device ip: {device_ip}")

        # Fetches the DUT mac address
        dut_mac_address = self.wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        # Validating the power management bit
        packet_filter1 = f'wlan.fc.pwrmgt == 1 and wlan.addr == {dut_mac_address}'

        # This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # # Enables the bt power save in DUT
        self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
        time.sleep(5)

        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        assert status == 1
        logger().info(f"ping is successful")

        self.wifi_sniffer.interfaces.capture.stop_capture()
        assert self.wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count'], 'Unable to find power management bit in sniffer'
        logger().info(f"Verified device is in power save")

        if self.run_iperf:
            self.run_traffic()

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
                                                             ble_scan_window=self.ble_scan_window, timeout=1000)

        logger().info(f"Remote device found in scan results ,BLE scanning is successful")





#thread for wifi scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        #enables the scan in dut on channel 0
        scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
        logger().info(f"scan results : {scan_results}")
        assert (len(scan_results) >= 1)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_advertising_interval_of_20ms(wifi_dut, wifi_access_point, ble_client):
       with ScanThread(wifi_dut, wifi_access_point),BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_AP_connection_with_BLE_advertising_interval_of_20ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
    testcase = "test_AP_connection_with_BLE_advertising_interval_of_20ms"
    with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)





@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_Wifi_Data_transfer_with_BLE_advertising_interval_of_20ms(wifi_sniffer,wifi_dut,\
                                                                       wifi_access_point,wifi_client,\
                                                                  run_iperf1,ble_client):
    testcase = "test_Wifi_Data_transfer_with_BLE_advertising_interval_of_20ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, run_iperf1), \
         BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_advertising_interval_of_10240ms(wifi_dut, wifi_access_point, ble_client):
       with ScanThread(wifi_dut, wifi_access_point),\
               BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_AP_connection_with_BLE_advertising_interval_of_10240ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
    testcase = "test_AP_connection_with_BLE_advertising_interval_of_10240ms"
    with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), \
            BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)





@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_Wifi_Data_transfer_with_BLE_advertising_interval_of_10240ms(wifi_sniffer,wifi_dut,\
                                                                       wifi_access_point,wifi_client,\
                                                                  run_iperf1,ble_client):
    testcase = "test_Wifi_Data_transfer_with_BLE_advertising_interval_of_10240ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, run_iperf1), \
         BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_Scan_interval_of_10240ms(wifi_dut, wifi_access_point, ble_client):
       with ScanThread(wifi_dut, wifi_access_point),\
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=8000):
           time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_AP_connection_with_BLE_Scan_interval_of_10240ms(wifi_sniffer,wifi_dut, wifi_access_point, ble_client):
       testcase = "test_AP_connection_with_BLE_Scan_interval_of_10240ms"
       with WifiThread(wifi_sniffer,wifi_dut, wifi_access_point,testcase=testcase), \
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=8000):
        time.sleep(5)



@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.TCP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,

    }
 )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_Data_transfer_with_BLE_Scan_interval_of_10240ms(wifi_sniffer,wifi_dut,wifi_access_point,wifi_client,\
                                                                  run_iperf1,ble_client):

    testcase = "test_Wifi_Data_transfer_with_BLE_Scan_interval_of_10240ms"

    with WifiThread(wifi_sniffer,wifi_dut,wifi_access_point,testcase,wifi_client, run_iperf1), \
         BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=8000):
        time.sleep(15)



@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
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
    #with Wifi_http_download_Thread(wifi_dut, wifi_access_point, http_server, index_path), \
    with WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase,http_server = http_server, index_path=index_path),\
         BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
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
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
        | RS9116TCPIPFeatureBitMap.SSL
        | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
        | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
    },
)

@pytest.mark.dut("rs9116_sapi")
@pytest.mark.http_server("raspi_lighttpd")
@pytest.mark.parametrize("index_path", {"100MB.html"})
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_http_download_with_BLE_scan_interval_of_10240ms_and_scan_window_of_10000ms(wifi_sniffer,http_server,\
                                                wifi_dut, wifi_access_point,ble_client,index_path):
       testcase = "test_Wifi_http_download_with_BLE_scan_interval_of_10240ms_and_scan_window_of_10000ms"
       with WifiThread(wifi_sniffer, wifi_dut, wifi_access_point, testcase,http_server = http_server, index_path=index_path), \
            BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=10000):
            time.sleep(15)




