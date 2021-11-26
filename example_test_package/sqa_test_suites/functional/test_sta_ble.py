import pytest
from utils.iperf.Iperf_constants import IperfConstants
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

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        # Join Wi-Fi Access Point
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        time.sleep(10)

#this thread used for sta+ble as a slave
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):

        if ( self.mode == "ble_master"):

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

            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)

            # Now, we can restart advertising...
            self.wifi_dut.interfaces.wifi.ble_start_advertising()
            # ...and stop again
            self.wifi_dut.interfaces.wifi.ble_stop_advertising()

#thread for scan functionality
class ScanThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list, select_channel_all):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.channel_2_4_list = channel_2_4_list
        self.channel_5_list = channel_5_list
        self.select_channel_all = select_channel_all


    def run(self):
        channel_bitmap_2_4 = 0
        channel_bitmap_5 = 0
        scan_feature_extend = 0

        if len(self.channel_2_4_list):
            channel_list = self.channel_2_4_list
            scan_expected_time = 0
            for count in channel_list:
                channel_bitmap_2_4 += 1 << (count - 1)
                scan_expected_time += 100

            channel_bitmap_5 = 0
            scan_feature_extend = 0
            for channel in channel_list:

                # initiates the access point with channel given in list
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)

                with TimeMeasurer() as t:

                    # enables the scan in DUT with the given channel bitmap value
                    scan_results = self.wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                                        scan_bitmap_2_4=channel_bitmap_2_4,
                                                                                        scan_bitmap_5=channel_bitmap_5,
                                                                                        scan_feature=scan_feature_extend)
                    logger().info(scan_results)
                    assert len(scan_results) >= 1

                    channel_selected = 0
                    for count in scan_results:
                         for device_channel in channel_list:
                               if count.rf_channel == device_channel:
                                   channel_selected = channel_selected + 1

                assert ( t.duration < 1 )
                logger().info(f"Scan in {t.duration} seconds")

        if len(self.channel_5_list):
            channel_list = self.channel_5_list
            scan_expected_time = 0

            for count in channel_list:
                channel_bitmap_5 += 1 << (count - 1)
                scan_expected_time += 100

            channel_bitmap_2_4 = 0
            scan_feature_extend = 0
            for channel in channel_list:

                # initiates the access point with channel given in list
                self.wifi_access_point.interfaces.wifi.start_ap(channel=channel)

                with TimeMeasurer() as t:

                    # enables the scan in DUT with the given channel bitmap value
                    scan_results = self.wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                                            scan_bitmap_2_4=channel_bitmap_2_4,
                                                                                            scan_bitmap_5=channel_bitmap_5,
                                                                                            scan_feature=scan_feature_extend)
                    logger().info(scan_results)
                    assert len(scan_results) >= 1

                    channel_selected = 0
                    for count in scan_results:
                        for device_channel in channel_list:
                              if count.rf_channel == device_channel:
                                    channel_selected = channel_selected + 1

                assert (t.duration < 1)
                logger().info(f"Scan in {t.duration} seconds")

        if self.select_channel_all:

                with TimeMeasurer() as t:
                    # enables the scan in dut on channel 0
                    scan_results = self.wifi_dut.interfaces.wifi.scan(channel=0, ssid=None)
                assert (t.duration < 1.5)
                logger().info(scan_results)


#rejoin thread for the ap when ap lost and deauth frame scenario
class RejoinThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point, Aplost , deauth_frame):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point=wifi_access_point
        self.deauth_frame = deauth_frame
        self.Aplost = Aplost

    def run(self):
       if self.Aplost:
         self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
         self.wifi_access_point.interfaces.wifi.stop_ap()
         self.wifi_dut.interfaces.wifi.rejoin()
         time.sleep(2)

       if self.deauth_frame:
         self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)

#tcp thoughput thread for rx adn tx packets
class TCPPacketThread(ThreadBase):
    def __init__(self, wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        super().__init__()
        self.wifi_networked_dut = wifi_networked_dut
        self.wifi_access_point = wifi_access_point
        self.wifi_client = wifi_client
        self.run_iperf = run_iperf1

    def run(self):
        iperf = IPerfFixture(
            'test1',
            self.run_iperf,
            self.wifi_access_point,
            self.wifi_networked_dut,
            self.wifi_client,
        )
        iperf.run()
        time.sleep(10)
        logger().info("this is IPerf")

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)

#testcase1 #testcase2 for sta+ble master functionality
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_sta_ble_dut_as_master(wifi_dut, ble_client, wifi_access_point):
    mode = "ble_master"
    with WifiThread(wifi_dut, wifi_access_point), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)

#testcase3 for Sta+ble slave functionality
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_sta_ble_dut_as_slave(wifi_dut, ble_client, wifi_access_point):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 0
             }
        )
#testcase9 for for selective channels in 2.4 ghz + ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
def test_threading_selective_channels_2_4(wifi_dut , ble_client, wifi_access_point):
    select_channel_all = False
    channel_2_4_list = [1, 6, 11]
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list,select_channel_all) , BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

#testcase10 for all channels in 2.4 ghz +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=[ 'init'])
def test_threading_all_channels_2_4(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list, select_channel_all) , BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 1
            }
)
#testcase11 for selective channels in 5 ghz +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": "11g"})
def test_threading_selective_channels_5(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = False
    channel_2_4_list = []
    channel_5_list = {1:36, 2:44, 3:48}
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list, select_channel_all) , BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)

#testcase12 for all channels in 5 ghz +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"standard": "11g"})
def test_threading_all_channels_5(wifi_dut, wifi_access_point, ble_client):
    select_channel_all = True
    channel_2_4_list = []
    channel_5_list = []
    mode = "ble_slave"
    with ScanThread(wifi_dut, wifi_access_point, channel_2_4_list, channel_5_list, select_channel_all) , BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)


@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 0
            }
)

#testcase 13 for rejoin functionality when ap lost +ble #testcase 14 for ap user disconnection +ble  #testcase15 ap user disconnection +ble
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config(wifi = {'standard': "11g"})
def test_threading_sta_ble_rejoin(wifi_dut, wifi_access_point, ble_client):
    Aplost = True
    deauth_frame = False
    mode = "ble_slave"
    with RejoinThread(wifi_dut, wifi_access_point, Aplost, deauth_frame), BleThread_connection(wifi_dut, ble_client, mode) :
        time.sleep(15)


@pytest.mark.config(
        "wifi_dut",
        wifi=
        {
            "oper_mode": 0,
            "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
            "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
            "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
            "band": 0
            }
)

#testcase16 for rejoin functionality when deauth frame
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={ "passphrase": 'thisisatestjyothi', 'standard': "11g"})
def test_threading_sta_ble_rejoin_deauth(wifi_dut, wifi_access_point, ble_client):
    Aplost = False
    deauth_frame = True
    mode = "ble_master"
    with RejoinThread(wifi_dut, wifi_access_point, Aplost, deauth_frame), BleThread_connection(wifi_dut, ble_client, mode) :
        time.sleep(15)


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
#testcase17 for client mode(rx) packet throughput +ble
@pytest.mark.config(wifi = {'standard': "11g"})
def test_throughput_wifi_bt_1(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, ble_client):
    mode = "ble_slave"
    with TCPPacketThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
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
#testcase18 for server mode(tx) packet throughput +ble
@pytest.mark.config(wifi = {'standard': "11g"})
def test_throughput_wifi_bt_2(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1, ble_client):
    mode = "ble_slave"
    with TCPPacketThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(5)

