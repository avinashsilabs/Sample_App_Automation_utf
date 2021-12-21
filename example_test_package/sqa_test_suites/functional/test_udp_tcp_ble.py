from interfaces.wifi import WlanError

from utils.iperf.Iperf_constants import IperfConstants
import pytest
from utils.logger import get_logger

from integration_tests.common import logger
from interfaces.iperf.fixtures import IPerfFixture, iperf

from utils.iperf.Iperf_constants import IperfConstants
from utils.thread_base import ThreadBase
import time
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from interfaces.bluetooth import BTSocketRole
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap


def logger():
    return get_logger(__name__)

"""
setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)    
Test Steps:    
        Step1 : Configuration of DUT in BT/Wlan.
        Step2 : Verify the connection to AP
        Step3 : Verify the Bleconnection

Author:
        Jyothi Nagireddy
"""

#this thread used for data throughput
class wifiDatathroughputThread(ThreadBase):
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
        time.sleep(10)
        iperf.run()
        logger().info("this is IPerf END")

# this thread used for ble connectionn as a slave/master
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        self.logger.info('this is BLE run')
        time.sleep(5)
        if ( self.mode == "ble_master"):
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None

            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None

            # Start scanning and connect to ble client
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=15)

            timeout = 120
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

            # Disconnect
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if ( self.mode == "ble_slave"):

        # Set up DUT for BLE advertising
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        #     time.sleep(2)
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
            found_devices = self.ble_client.interfaces.bluetooth.get_devices()
            time.sleep(3)
            assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
            )
            self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
            time.sleep(40)

            self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


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
        "band": 2
    }
)
#Tcp rx packet loss #tcp rx throughput in WPA2-AES mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_rx_C20223_C20230(ble_client, wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

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
        "band": 2
    }
)
#txp tx in WPA2-Mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_tx_C20229(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#udp rx in WPA2-AES mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_rx_C20230(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#udp tx in WPA2-AES mode
@pytest.mark.config('wifi_access_point', wifi={"security": "WPA2", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_tx_C20229(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)


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
        "band": 2
    }
)
#throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_rx_C20203(ble_client, wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

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
        "band": 2
    }
)
#throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_tcp_tx_C20203(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.CLIENT_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_rx_C20203(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)

@pytest.mark.parametrize('run_iperf1', [
    {IperfConstants.IPERF_TEST_CONFIG: {IperfConstants.IPERF_TEST_HOST_ROLE: IperfConstants.SERVER_MODE,
                                        IperfConstants.IPERF_TEST_PROTOCOL: IperfConstants.UDP}
     }])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.
            OpenMode | RS9116FeatureBitMap.PSKSecurity,
        "band": 2
    }
)
#throughput functionality in open mode
@pytest.mark.config('wifi_access_point', wifi={"security": "OPEN", "cipher": 'AES'})
def test_threading_sta_ble_dut_udp_tx_C20203(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                      ble_client):
    mode = "ble_slave"
    with wifiDatathroughputThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(10)


