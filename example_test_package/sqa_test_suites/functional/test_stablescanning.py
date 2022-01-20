import pytest
from interfaces.iperf.iperf_constants import IperfConstants
from utils.time_measurer import TimeMeasurer
from utils.logger import get_logger
from interfaces.iperf.fixtures import IPerfFixture, iperf
from interfaces.iperf.iperf_constants import IperfConstants
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
        Step1 : Configuration of DUT in BT/Wlan.
        Step2 : Verify the connection to AP
        Step3 : Verify the Bleconnection

Author:
        Jyothi Nagireddy
"""

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
        # Enables the wifi power save in dut
        self.wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)

#this thread used for sta+ble as a slave
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
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
        assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
        )

@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
# testcase2 for Sta+ble slave functionality
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_threading_sta_ble_dut_C20184(wifi_dut, ble_client, wifi_access_point):
    mode = "ble_slave"
    with WifiThread(wifi_dut, wifi_access_point), BleThread_connection(wifi_dut, ble_client, mode):
        time.sleep(15)