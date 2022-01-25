import pytest
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from interfaces.iperf.fixtures import IPerfFixture, iperf
from utils.iperf.Iperf_constants import IperfConstants
from utils.iperf.iperf_utils import ping
from interfaces.wifi import WlanError
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116TCPIPFeatureBitMap
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
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):

        # This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # # Enables the bt power save in DUT
        #self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

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
        # Initiate ping from third party wifi-client to DUT
        status = ping(device_ip, 10)
        logger().info(f"ping status {status}")

        assert status == 1



#tcp thoughput thread for rx adn tx packets
class TCPPacketThread(ThreadBase):
    def __init__(self,wifi_access_point, wifi_dut, wifi_client, run_iperf1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.run_iperf = run_iperf1

    def run(self):
        # This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # # Enables the bt power save in DUT
        #self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")
        time.sleep(5)
        # This API Enables the DHCP in DUT
        result = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"


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



# this thread used for wifi join
class Wifi_http_download_Thread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point,http_server,index_path):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.http_server = http_server
        self.index_path = index_path

    def run(self):

        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        logger().info(f"Successfully connected to AP")
        time.sleep(10)
        #starts the dhcp in dut
        result = self.wifi_dut.interfaces.wifi.start_ip(timeout=30)
        assert isinstance(
            result, self.wifi_dut.interfaces.wifi.IPConfig
        ), f"Failed to get IP address. Result = {result}"

        # This API Enables the wifi power save mode in DUT
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

        # Enables the bt power save in DUT
        #self.wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

        self.wifi_dut.interfaces["http"] = self.wifi_dut.interfaces.wifi

        # API used to get the http data
        self.wifi_dut.interfaces.http.http_get(self.http_server.interfaces.http, self.index_path)
        logger().info(f"Http download is success")


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
        self.wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=self.adv_int, \
                                                            ble_adv_int_max=self.adv_int)

        logger().info(f"Started advertising DUT")

        # Begin Scanning for BLE devices
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None

        logger().info(f"Started scan from remote BLE device")

        logger().info("\n***********{}**********\n".format(bt_client_address))


        for i in range(0,5):

            time.sleep(10)

            if self.adv_int > 1000:

                time.sleep(20)

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

        #self.wifi_dut.interfaces.wifi.ble_stop_scanning(timeout=50)



#this thread used for sta+ble as a slave
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):

        if ( self.mode == "ble_master"):
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
            logger().info(f"Initiating connection this can take upto 120 seconds....")
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
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                    == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )

            # Not legal to start advertising if we're already advertising...
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_start_advertising()
            assert exc_info.value.error_code == 0x4E0C  # "command disallowed"

            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)

            # Connecting will automatically stop advertising
            with pytest.raises(WlanError) as exc_info:
                self.wifi_dut.interfaces.wifi.ble_stop_advertising()
            assert exc_info.value.error_code == 0x4E0C  # "command disallowed"



#thread for scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
            # enables the scan in dut on channel 0
            scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
            logger().info(scan_results)
            time.sleep(5)






@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_advertising_interval_of_20ms(wifi_dut, wifi_access_point, ble_client):
       with ScanThread(wifi_dut, wifi_access_point), BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_AP_connection_with_BLE_advertising_interval_of_20ms(wifi_dut, wifi_access_point, ble_client):
       with WifiThread(wifi_dut, wifi_access_point), BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
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

def test_Wifi_Data_transfer_with_BLE_advertising_interval_of_20ms(wifi_dut,\
                                                                       wifi_access_point,wifi_client,\
                                                                  run_iperf1,ble_client):

    with TCPPacketThread(wifi_access_point, wifi_dut, wifi_client, run_iperf1), \
         BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_Wifi_scan_with_BLE_advertising_interval_of_10240ms(wifi_dut, wifi_access_point, ble_client):
       with ScanThread(wifi_dut, wifi_access_point), BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")

def test_AP_connection_with_BLE_advertising_interval_of_10240ms(wifi_dut, wifi_access_point, ble_client):
       with WifiThread(wifi_dut, wifi_access_point), BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
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
def test_Wifi_Data_transfer_with_BLE_advertising_interval_of_10240ms(wifi_dut,wifi_access_point,\
                                                                     wifi_client,run_iperf1, ble_client):
    with TCPPacketThread(wifi_access_point, wifi_dut, wifi_client, run_iperf1), \
         BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
        time.sleep(5)






@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
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

def test_Wifi_http_download_BLE_advertising_interval_of_20ms(http_server,wifi_dut, wifi_access_point,\
                                                             ble_client,index_path):
    with Wifi_http_download_Thread(wifi_dut, wifi_access_point, http_server, index_path), \
         BleThread_Advertise(wifi_dut, ble_client, adv_int=20):
        time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
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
def test_Wifi_http_download_BLE_advertising_interval_of_10240ms(http_server,wifi_dut, wifi_access_point,\
                                                             ble_client,index_path):
    with Wifi_http_download_Thread(wifi_dut, wifi_access_point, http_server, index_path), \
                       BleThread_Advertise(wifi_dut, ble_client, adv_int=10240):
                    time.sleep(5)





@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_Wifi_scan_with_BLE_Scan_interval_of_10240ms(wifi_dut, wifi_access_point, ble_client):
       with ScanThread(wifi_dut, wifi_access_point),\
               BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=8000):
           time.sleep(15)
#

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    },
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_AP_connection_with_BLE_Scan_interval_of_10240ms(wifi_dut, wifi_access_point, ble_client):
       with WifiThread(wifi_dut, wifi_access_point), BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,\
                                                                    ble_scan_window=8000):
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
def test_Wifi_Data_transfer_with_BLE_Scan_interval_of_10240ms(wifi_dut,wifi_access_point,wifi_client,\
                                                                  run_iperf1,ble_client):

    with TCPPacketThread(wifi_access_point, wifi_dut, wifi_client, run_iperf1),\
         BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=8000):
        time.sleep(15)




@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
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
def test_Wifi_http_download_with_BLE_scan_interval_of_10240ms_and_scan_window_of_10000ms(http_server,wifi_dut, wifi_access_point,\
                                                             ble_client,index_path):
       with Wifi_http_download_Thread(wifi_dut, wifi_access_point,http_server,index_path),\
            BleThread_Scan(wifi_dut, ble_client, ble_scan_interval=10240,ble_scan_window=10000):
            time.sleep(5)