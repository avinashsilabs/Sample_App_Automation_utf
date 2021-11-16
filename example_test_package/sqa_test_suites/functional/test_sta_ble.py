import pytest
from utils.thread_base import ThreadBase
import time
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from interfaces.bluetooth import BLEDeviceState

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


# this thread used for sta+ble connection as a slave
class BleThread_connection_dut_as_slave(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):

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
        self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
        self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)



#Test case1
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.http_server("raspi_lighttpd")

#calling testcase1 using thread
def test_threading_sta_ble_dut_as_slave(wifi_dut, ble_client, wifi_access_point):
    with WifiThread(wifi_dut, wifi_access_point), BleThread_connection_dut_as_slave(wifi_dut, ble_client):
        time.sleep(15)

