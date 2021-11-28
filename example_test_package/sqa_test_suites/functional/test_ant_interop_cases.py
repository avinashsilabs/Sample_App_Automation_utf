import pytest
from utils.thread_base import ThreadBase
import time
from interfaces.cli.rs_sapi_commands import RSSAPICommands
from devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes

def logger():
    return get_logger(__name__)

# this thread used for Ant initialization
class AntThread(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        # Initializes the ant process in dut
        self.wifi_dut.interfaces.wifi.ant_init(ant_cmd=12, ant_cmd_1=3, ant_cmd_2=1, ant_cmd_3=75, ant_cmd_4=0, ant_cmd_5=0, ant_cmd_resp=0)
        time.sleep(10)

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self, **config):
        # Join Wi-Fi Access Point
        self.wifi_access_point.interfaces.wifi.start_ap(**config)
        self.wifi_dut.interfaces.wifi.init()
        self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
        time.sleep(10)

# Runs ble thread
class BleThread(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        # Set up DUT for BLE advertising
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(5)

        self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
        self.ble_client.interfaces.bluetooth.get_devices()

# This Thread is used to run and inquiry the BT
class BtThread(ThreadBase):
    def __init__(self, wifi_dut, bt_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt_client = bt_client

    def run(self):
        self.wifi_dut.interfaces.wifi.bt_inquiry()
        time.sleep(10)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
    }
)
# Test case ID: 1.1.1.1 -- This case verifies the interop of ant,bt,ble,wifi connect to special charactered SSID
@pytest.mark.start_state("wifi_dut", wifi=['reset, init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
def test_ant_bt_ble_wifi_connect(wifi_dut, ble_client, wifi_access_point, bt_client):
    with AntThread(wifi_dut), BleThread(wifi_dut, ble_client),BtThread(wifi_dut, bt_client), WifiThread(wifi_dut, wifi_access_point) as wifi_thread:
        wifi_thread.run(ssid='#$@#$%@#$%@#$%@#$%@#$%@#$%@#$%')
        time.sleep(20)
