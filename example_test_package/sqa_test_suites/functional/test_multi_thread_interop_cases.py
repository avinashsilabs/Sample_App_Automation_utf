import pytest
from utf.utils.thread_base import ThreadBase
import time
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes
from utf.utils.logger import get_logger
from utf.utils.time_measurer import TimeMeasurer

def logger():
    return get_logger(__name__)

"""setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
    
    Test Steps:
        1. Configure the DUT in Wlan coex mode for 2.4Ghz
        2. ANT stack initiation with ant thread
        3. Join the access point and enable the dhcp with wifi thread
        4. Start ble scan and advertise in module with ble thread
        5. Start bt inquiry in DUT with bt thread
    
    NOTE: Use the ANT supported EVK(v1.5) with ANT supported rs9116 firmware
    
    Author: Ravi Nemali
 
"""

# this thread used for Ant initialization
class AntThread(ThreadBase):
    def __init__(self, wifi_dut):
        super().__init__()
        self.wifi_dut = wifi_dut

    def run(self):
        # Initializes the ant process in dut
        self.wifi_dut.interfaces.wifi.ant_init(ant_cmd=12, ant_cmd_1=3, ant_cmd_2=1, ant_cmd_3=74, ant_cmd_4=0, ant_cmd_5=0, ant_cmd_resp=0)
        time.sleep(10)

# this thread used for wifi join
class WifiThread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        print(self.wifi_access_point.config["interfaces"]["wifi"]["ssid"], "self.wifi_access_point.config")
        print(self.wifi_access_point.defaults, "self.wifi_access_point.defaults")

    def run(self):
        # Join Wi-Fi Access Point
        self.wifi_access_point.interfaces.wifi.start_ap()
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
        time.sleep(20)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connect to special charactered SSID
def test_ant_bt_ble_wifi_connect1(wifi_dut, ble_client, wifi_access_point, bt_client):
    wifi_access_point.config["interfaces"]["wifi"]["ssid"] = "#@#@#@#$@#$@#$@#$"
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        time.sleep(20)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connect to DOTTED charactered SSID
def test_ant_bt_ble_wifi_connect2(wifi_dut, ble_client, wifi_access_point, bt_client):
    wifi_access_point.config["interfaces"]["wifi"]["ssid"] = ".........."
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        time.sleep(20)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connect to 32 bytes SSID
def test_ant_bt_ble_wifi_connect3(wifi_dut, ble_client, wifi_access_point, bt_client):
    wifi_access_point.config["interfaces"]["wifi"]["ssid"] = "asdfghjklkjhgfdsazxcvbhnjmkloiu"
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        time.sleep(20)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connect to 63 bytes lenght PSK
def test_ant_bt_ble_wifi_connect4(wifi_dut, ble_client, wifi_access_point, bt_client):
    wifi_access_point.config["interfaces"]["wifi"]["passphrase"] = "asdfghjklkjhgfdsazxcvbhnjmkloiupoiuytrewqasfdghjklmnbvcxsdert"
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        time.sleep(20)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connect and get dhcp IP of DUT
def test_ant_bt_ble_wifi_connect5(wifi_dut, ble_client, wifi_access_point, bt_client, wifi_associated_dut):
    wifi_access_point.config["interfaces"]["wifi"]["passphrase"] = "testdhcp"
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        time.sleep(20)
        result = wifi_associated_dut.interfaces.wifi.start_ip()
        assert isinstance(
            result, wifi_associated_dut.interfaces.wifi.IPConfig
        )
        time.sleep(10)

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connect and verifies the ping
def test_ant_bt_ble_wifi_connect6(wifi_dut, ble_client, wifi_access_point, bt_client,wifi_networked_dut):
    wifi_access_point.config["interfaces"]["wifi"]["passphrase"] = "testping"
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        with TimeMeasurer() as t:
            wifi_networked_dut.interfaces.wifi.ping()
        logger().info(f"Ping completed in {t.duration} seconds")

@pytest.mark.config (
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE | RS9116CoexMode.ANT,
    }
)
# This case verifies the interop of ant,bt,ble,wifi connection to hidden mode AP
def test_ant_bt_ble_wifi_connect7(wifi_dut, ble_client, wifi_access_point, bt_client):
    wifi_access_point.config["interfaces"]["wifi"]["passphrase"] = "testhiddenmodeap"
    wifi_access_point.config["interfaces"]["wifi"]["broadcast_ssid"] = False
    with AntThread(wifi_dut),BtThread(wifi_dut, bt_client),BleThread(wifi_dut, ble_client),WifiThread(wifi_dut, wifi_access_point):
        time.sleep(10)