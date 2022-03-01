import time
import pytest

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
    RS9116MqttQos,
    DeviceConstants,
    )
from utf.utils.iperf.iperf_utils import get_host_ip
from utf.utils.logger import get_logger
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.iperf.fixtures import IPerfFixture, iperf
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf_wiseconnect.utils.rs911x_version import parse_version
from utf.utils.time_measurer import TimeMeasurer
from utf.utils.stopwatch import Stopwatch
import string
import random
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.wifi import WlanError


def logger():
    return get_logger(__name__)


def ApWirelessOff(wifi_access_point, wait_time, logger):
    time.sleep(wait_time)
    logger.info(f"Disabling Wireless in AP")
    wifi_access_point.interfaces.wifi.stop_ap()
    time.sleep(5)
    logger.info(f"Enabling Wireless in AP")
    wifi_access_point.interfaces.wifi.start_ap()


class wifiJoinThread(ThreadBase):
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
        time.sleep(5)
        iperf.run()
        logger().info("this is IPerf END")


# this thread used for sta+ble as a slave
class BleThread_connection(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode

    def run(self):
        self.logger.info('this is BLE run')
        time.sleep(5)
        if self.mode == "ble_master":
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None

            # Start ble client
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None

            # Start scanning and connect to ble client
            logger().info("Scanning to ble client")
            self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=bt_client_address, timeout=15)

            timeout = 120
            logger().info("Connecting to ble client")
            self.wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=bt_client_address, timeout=timeout)

            # Disconnect
            logger().info("Disconnect to ble client")
            self.wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=bt_client_address)

        if self.mode == "ble_slave":
            # Set up DUT for BLE advertising
            logger().info("Starts BLE advertising")
            bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
            assert bt_dut_address is not None
            self.wifi_dut.interfaces.wifi.ble_start_advertising()

            # Begin Scanning for BLE devices
            logger().info("Scanning for BLE devices")
            time.sleep(3)
            bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
            assert bt_client_address is not None
            time.sleep(3)
            self.ble_client.interfaces.bluetooth.stop_scanning()

            # See that we found our device
            logger().info("Checks our device is found")
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


class Ble_Data_Transfer(ThreadBase):
    def __init__(self, wifi_dut, ble_client):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client

    def run(self):
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        data1 = "LzY0"
        data2 = "K09x"
        data3 = "Mx3Y"

        # Set up BLE Server on DUT
        bt_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert bt_dut_address is not None
        self.wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        self.wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        self.wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data1)

        # Start advertising
        logger().info("Ble start advertising")
        self.wifi_dut.interfaces.wifi.ble_start_advertising()

        # Begin Scanning for BLE devices
        logger().info("Scanning for BLE devices")
        bt_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
        assert bt_client_address is not None
        time.sleep(5)
        self.ble_client.interfaces.bluetooth.stop_scanning()

        # See that we found our device
        logger().info("Searching for our devices")
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (
                found_devices[self.wifi_dut.interfaces.wifi.ble_address]
                == self.wifi_dut.interfaces.wifi.ble_advertising_data
        )

        # connecting to dut
        logger().info("Connecting to dut")
        self.ble_client.interfaces.bluetooth.connect(bt_dut_address)
        time.sleep(2)

        # resolving charecteristic
        logger().info("Resolving characteristic")
        bus = self.ble_client.interfaces.bluetooth.bus
        servs, chars = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        assert len(servs) > 0
        assert len(chars) > 0

        char, char_props = self.ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic \
            (bus, services=servs, service_uid=service_uid, char_uid=char_uid)
        assert char is not None
        assert len(char_props) > 0

        # read value - Notifications not enabled
        logger().info("read value")
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data1

        # subscribe to notifications
        logger().info("subscribe to notifications")
        self.ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                     char_uid=char_uid)
        # time.sleep(0.5)
        time.sleep(35)

        # notify only
        logger().info("notify")
        self.wifi_dut.interfaces.wifi.ble_notify_value()

        # write/read new value - Notifications enabled
        logger().info("write/read new value")
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data2)
        time.sleep(0.1)
        result = self.ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(characteristic=char)
        assert result == data2

        # write value - Notifications enabled
        logger().info("write value")
        self.ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(characteristic=char, data=data3)

        # auto notify
        logger().info("auto notify")
        self.ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char,
                                                                                     char_uid=char_uid)
        self.wifi_dut.interfaces.wifi.ble_start_notify_value(interval_ms=500, count=2)
        time.sleep(1)

        # subscribe to notifications
        logger().info("subscribe to notifications")
        self.ble_client.interfaces.bluetooth.gatt_adapter.disable_notifications(characteristic=char)
        self.ble_client.interfaces.bluetooth.gatt_adapter.unsubscribe_to_notifications(char_uid=char_uid)
        time.sleep(0.5)

        # notify only - disabled notifications - should raise exception
        with pytest.raises(WlanError) as exc_info:
            self.wifi_dut.interfaces.wifi.ble_notify_value()
        assert exc_info.value.error_code == 0x21

        # assert received notifications
        logger().info("assert will received notifications")
        notifications = self.ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(notifications)
        assert len(notifications) == 6
        assert notifications[0] == data1
        assert notifications[1] == data2
        assert notifications[2] == data2
        assert notifications[3] == data3
        assert notifications[4] == data3
        assert notifications[5] == data3

        # disconnecting from dut
        logger().info("disconnecting from dut")
        self.ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


def test_firmware_version_TC18(wifi_dut):
    expected_version = parse_version()
    if expected_version is None:
        pytest.skip("No firmware version for 9116x in manifest, skipping test_version")
    logger().info(f"Expected Firmware version: {expected_version}")
    result = wifi_dut.interfaces.wifi.version()
    logger().info(f"Actual Firmware version: {result}")
    assert result == expected_version


# STA + BLE DATA TRANSFER
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
def test_threading_sta_ble_data_udp_tx_TC24(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                            ble_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), \
            Ble_Data_Transfer(wifi_dut, ble_client):
        time.sleep(30)


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
def test_threading_sta_ble_data_udp_rx_TC24(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                            ble_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), Ble_Data_Transfer(wifi_dut,
                                                                                                           ble_client):
        time.sleep(40)


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
def test_threading_sta_ble_data_tcp_tx_TC24(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                            ble_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), Ble_Data_Transfer(wifi_dut,
                                                                                                           ble_client):
        time.sleep(20)


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
def test_threading_sta_ble_data_tcp_rx_TC24(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client, run_iperf1,
                                            ble_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1), Ble_Data_Transfer(wifi_dut,
                                                                                                           ble_client):
        time.sleep(20)

#
# @pytest.mark.config(
#     "wifi_dut",
#     {
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
#         "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan,
#         "band": 1
#         }
#     )
# @pytest.mark.start_state("wifi_dut", wifi=['init'])
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
# @pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "channel": 56})
# # This test case verifies the dut connect functionality in 5ghz dfs channel mode of access point
# def test_join_5ghz_dfs_channel_testcase20(wifi_dut, wifi_access_point):
#     with TimeMeasurer() as t:
#         # enables the rejoin feature on dut
#         logger().info("enabling Re-joining")
#         status = wifi_dut.interfaces.wifi.rejoin()
#         assert status
#
#         # Joins the access point with given ssid and password
#         logger().info("Joining the AP")
#         status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
#         assert status, 'Unable to join ap '
#
#         # assigns and enables the dhcp in dut
#         logger().info("Starting dhcp")
#         result = wifi_dut.interfaces.wifi.start_ip()
#
#         assert isinstance(
#             result, wifi_dut.interfaces.wifi.IPConfig
#             ), f"Failed to get IP address. Result = {result}"
#         device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
#
#         # Enables the wifi power save in dut
#         logger().info("enabling wifi power save")
#         enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(8)
#         assert enable_wifi_ps, 'failed to enable'
#
#         # Enables the bt power save in dut
#         logger().info("enabling bt power save")
#         enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(8)
#         assert enable_bt_ps, 'failed to enable'
#
#         # initiates the ping in dut
#         logger().info("pinging to dut ip")
#         status = ping(device_ip, 10)
#         assert status == 1
#     logger().info(f"Associated in {t.duration} seconds")
#
#
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
def test_throughput_wifi_alone_tcp_tx_testcase1(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client,
                                                run_iperf1,
                                                bt_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
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
        "band": 2
        }
    )
def test_throughput_wifi_alone_tcp_rx_testcase1(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client,
                                                run_iperf1,
                                                bt_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        time.sleep(15)


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
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
def test_throughput_wifi_alone_udp_tx_testcase3(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client,
                                                run_iperf1,
                                                bt_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        time.sleep(15)


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
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
def test_throughput_wifi_alone_udp_rx_testcase3(wifi_dut, wifi_networked_dut, wifi_access_point, wifi_client,
                                                run_iperf1,
                                                bt_client):
    with wifiJoinThread(wifi_access_point, wifi_networked_dut, wifi_client, run_iperf1):
        time.sleep(15)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        # "first_time_retry": 0,
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "disable_store_config"])
def test_store_config_open_testcase12(wifi_access_point, wifi_dut):
    # DUT connects to AP after join_ap API is executed
    logger().info("Joining the Wifi Access Point")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    logger().info("DUT gets ipaddress through DHCP ")
    wifi_dut.interfaces.wifi.start_ip()
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device before store configuration"

    # Save the wireless configuration in the flash
    logger().info("Save the Wireless Configuration in the flash")
    wifi_dut.interfaces.wifi.config_save()
    # Enable the wireless configuration in the flash
    logger().info("Enables the Wireless Configuration in the flash")
    wifi_dut.interfaces.wifi.config_enable(config=RS9116StoreConfiguration.CfgEnable)
    # deinit
    logger().info("deinit")
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(5)
    # init
    logger().info("Wireless Initialization ")
    wifi_dut.interfaces.wifi.wireless_init()
    time.sleep(10)
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    logger().info("Enables the Wifi power save")
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    logger().info("Enables the BT Power SAve")
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)

    # Ping to dut from third party device
    status = ping(device_ip, 10)
    assert status == 1, "DUT is not responding to ping request from third party device after store configuration"
    time.sleep(5)


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default
                          | RS9116TCPIPFeatureBitMap.SSL
                          | RS9116TCPIPFeatureBitMap.LoadSSLCertificatesToRAM
                          | RS9116TCPIPFeatureBitMap.LoadPublicPrivateCerts,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default

        },
    )
@pytest.mark.parametrize("wireless_firmware", ["/RS9116.2.5.0.4.rps"])
# These test case verifies the firmware upgrade in DUT over the http connection in wlan mode
def test_http_otaf_testcase53(http_server, wifi_dut, wifi_access_point, wireless_firmware):
    # Joins the AP with given ssid and passphrase
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # Enables and assign the dhcp in DUT
    wifi_dut.interfaces.wifi.start_ip()

    # This API gets the host ip for the http server
    host_ip = get_host_ip()
    start_time = time.perf_counter_ns()
    async_timestamp = 0

    # performs the firmware upgrade on DUT over the http port
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80, wireless_firmware)
    time.sleep(30)

    # API fetches the DUT otaf status
    wifi_dut.interfaces.wifi.get_http_otaf_status()
    time.sleep(1)

    # fetches the async events generated from the DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    if len(events):
        for event in events:
            if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                async_timestamp = event.timestamp

    if not async_timestamp:
        logger().info(f"Asynchronous message is not received after otaf over http")
    else:
        time_duration = (async_timestamp - start_time) / 1000000000
        logger().info(f"Time taken to upgrade firmware using http otaf {time_duration} seconds")

    # API does soft reset on DUT
    wifi_dut.interfaces.wifi.reset_soft()
    time.sleep(60)

    # performs the wifi initialization
    wifi_dut.interfaces.wifi.init()

    # gets DUT fw version
    wifi_dut.interfaces.wifi.version()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
def test_ssl_client_tx_rejoin_length_1460_testcase2(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    pkt_count = 10000
    bytes_sent = (pkt_count * buffer_length)
    # DUT connects to AP after join_ap API is executed
    logger.info(f"sending rejoin params with rejoin_max=40, scan_interval=6, beacon_missedcount=40 and  "
                f"first_time_retry=0")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=40,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.data_receive(1, pkt_count, buffer_length, pkt_rcv_timeout=120)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, timeout=600)
    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                         f"not matched on socket {1} "

    wifi_dut.interfaces.wifi.close_socket(sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"security": 'Open'})
def test_ssl_client_rx_while_rejoining_testcase2(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    logger.info(f"sending rejoin params with rejoin_max=40, scan_interval=6, beacon_missedcount=40 and  "
                f"first_time_retry=0")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=40,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    # DUT connects to AP after join_ap API is executed
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                           socket_flag=SocketType.ASYNCHRONOUS)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Set the tcp max retry for the socket
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    time.sleep(300)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"
    wifi_dut.interfaces.wifi.close_socket(sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_tx_rejoin_length_1460_testcase4(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    pkt_count = 10000
    bytes_sent = (pkt_count * buffer_length)
    logger.info(f"sending rejoin params with rejoin_max=40, scan_interval=6, beacon_missedcount=40 and  "
                f"first_time_retry=0")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=40,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    # DUT connects to AP after join_ap API is executed
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)

    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.data_receive(1, pkt_count, buffer_length, pkt_rcv_timeout=120)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    wifi_dut.interfaces.wifi.send_data_pkts(sock, buffer_length, pkt_count, timeout=600)
    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
    assert bytes_sent == bytes_received, f"Number of bytes sent by DUT and received on the remote peer " \
                                         f"not matched on socket {1} "

    wifi_dut.interfaces.wifi.close_socket(sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "disassociated"])
def test_ssl_client_rx_while_rejoining_testcase4(
        wifi_dut, wifi_access_point, ssl_server, logger
        ):
    pkt_count = ssl_server.interfaces.ssl.config['no_of_pkts']
    buffer_length = ssl_server.interfaces.ssl.config['buffer_length']
    port1 = ssl_server.interfaces.ssl.config['device_port1']
    logger.info(f"sending rejoin params with rejoin_max=40, scan_interval=6, beacon_missedcount=40 and  "
                f"first_time_retry=0")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=40,
                                    scan_interval=6,
                                    beacon_missedcount=40,
                                    first_time_retry=0)
    # DUT connects to AP after join_ap API is executed
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    # DUT gets ipaddress through DHCP process after start_ip API is executed
    wifi_dut.interfaces.wifi.start_ip()
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth mode
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    # The below api parses DUTs IP address
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
    # Open ssl server socket in remote device(Raspberry pi or static device)
    ssl_server.interfaces.ssl.start_server()
    # Open ssl client socket in the DUT
    sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SO_SSL_ENABLE,
                                                           socket_flag=SocketType.ASYNCHRONOUS)
    assert sock == 0

    # Enable ssl option for socket opened
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                               SocketOptions.SSL_ENABLE)
    # Set the tcp max retry for the socket
    wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                               SocketOptions.TCP_MAX_RETRY)
    # Socket binds at (device_ip, 5001) in DUT
    wifi_dut.interfaces.wifi.bind(sock, device_ip, port1)
    # ssl socket opened in DUT connects to the server
    wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=port1)

    ssl_server.interfaces.ssl.send_data(1, pkt_count, msg_length=buffer_length)
    thread = Thread(target=ApWirelessOff, args=(wifi_access_point, 20, logger), )
    thread.start()
    time.sleep(300)
    result = wifi_dut.interfaces.wifi.get_socket_rx_stats(sock)
    bytes_received = int(result.split(b":")[1])
    logger.info(f"bytes received on socket {sock} -> {bytes_received}")
    assert bytes_received == (pkt_count * buffer_length), "Packet loss observed while receive test"
    wifi_dut.interfaces.wifi.close_socket(sock)


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks mqtt connection, subscribe and publish feature when mqtt qos associated is qos1
def test_mqtt_qos1_connect_sub_publish_testcase_42(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

    capture_filename = "test_mqtt_qos1_connect_sub_publish_testcase_42"

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )

    # DUT connects to AP after join_ap API is executed
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    ip_address = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"DUT ip : {device_ip}")
    logger.info(f"Initiating ping to DUT ip {device_ip}")
    status = ping(device_ip, 10)
    if status == 1:
        logger.info(f"ping to DUT is successful")
    else:
        logger.info(f"ping to DUT is failed")
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )
    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1, qos=RS9116MqttQos.QOS1)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic2, qos=RS9116MqttQos.QOS1)

    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), qos=RS9116MqttQos.QOS1)
    time.sleep(1)
    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode(), qos=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by DUT"
    assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
    assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                 "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT received message with wrong QOS. expected is QOS1"
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break

    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic2, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
    assert msgs[0].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                 "message " \
                                                 "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 1
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "ca_cert": "ca-chain.cert.pem"
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.mqtt_server("raspi_mosquitto_tls")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["mqtt_disconnect", "wifi_powersave_disable", "disassociated"])
# The test case checks whether the DUT is able to connect to MQTT server over SSL when authentication feature is enabled
def test_mqtt_qos1_connect_sub_publish_ssl_testcase_41(
        wifi_sniffer, mqtt_server, mqtt_client, wifi_access_point, wifi_dut, logger
        ):
    topic1 = "mytesttopic/1"
    topic2 = "mytesttopic/2"
    # The api returns 100 bytes of random data
    message1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=100))
    # The api returns 200 bytes of random data
    message2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=200))

    capture_filename = "test_mqtt_qos1_connect_sub_publish_ssl_testcase_41"

    # configure interface for the channel of the access point
    wifi_sniffer.interfaces.capture.configure_interface(
        channel=wifi_access_point.interfaces.wifi.channel
        )
    wifi_dut.interfaces.wifi.scan(ssid=None)
    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    capture_filter = "ether host " + mac_address
    wifi_sniffer.interfaces.capture.start_capture(
        capture_file=f"{capture_filename}.pcap", capture_filter=capture_filter
        )
    # DUT connects to AP after join_ap API is executed
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    logger.info("get IP through dhcp")
    ip_address = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode(DeviceConstants.ENCODING)
    logger.info(f"DUT ip : {device_ip}")
    logger.info(f"Initiating ping to DUT ip {device_ip}")
    status = ping(device_ip, 10)
    if status == 1:
        logger.info(f"ping to DUT is successful")
    else:
        logger.info(f"ping to DUT is failed")
    # The below api puts DUT to power save
    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2)
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    # Both DUT and third-party mqtt client connects to MQTT server
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(
            mqtt_server.interfaces.mqtt
            )

    time.sleep(5)
    if wifi_dut.interfaces.mqtt.mqtt_client_is_connected:
        wifi_dut.interfaces.mqtt.mqtt_client_subscribe(topic1, qos=RS9116MqttQos.QOS1)
    if mqtt_client.interfaces.mqtt.mqtt_client_is_connected:
        mqtt_client.interfaces.mqtt.mqtt_client_subscribe(topic2, qos=RS9116MqttQos.QOS1)

    # publish a message with the third-party mqtt client
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic1, message1.encode(), qos=RS9116MqttQos.QOS1)
    time.sleep(1)
    # publish a message with the dut
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic2, message2.encode(), qos=RS9116MqttQos.QOS1)

    msgs = []
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break
    assert len(msgs) == 1, "No message is received by DUT"
    assert msgs[0].topic == topic1, "No message received by DUT on subscribed topic"
    assert msgs[0].payload.decode() == message1, "No message is received by DUT on subscribed topic or message " \
                                                 "received is wrong"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT received message with wrong QOS. expected is QOS1"
    sw = Stopwatch()
    while sw.elapsed_sec < 10:
        time.sleep(0.1)
        msgs = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msgs) == 1:
            break

    assert len(msgs) == 1, "No message is received by mqtt-client"
    assert msgs[0].topic == topic2, "No message received by mqtt-client on subscribed topic"
    assert msgs[0].qos == RS9116MqttQos.QOS1, "DUT sent message with wrong QOS. expected is QOS1"
    assert msgs[0].payload.decode() == message2, "No message is received by mqtt-client on subscribed topic or " \
                                                 "message " \
                                                 "received is wrong"

    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 1
    # The API returns asynchronous messages received by DUT
    events = wifi_dut.interfaces.wifi.get_async_events()
    assert len(events) == 0


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLANOnly,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "custom_features": RS9116CustomFeatureBitMap.RealTimeClockFromHost | RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3,
        }
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
# The test case checks whether the RTC(Real time clock) functionality is working fine in DUT
def test_wifi_set_get_rtc_testcase47(wifi_dut, wifi_access_point,logger):
    # DUT runs broadcast scan procedure when ssid is set to None
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    # The below two apis put DUT to power save. Both wifi power save and BT power save apis need to be called to put
    # DUT to power save in Wifi+bluetooth

    wifi_dut.interfaces.wifi.power_save(8)
    wifi_dut.interfaces.wifi.bt_power_save(8)

    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time = 100
    set_time_sec = ((set_minutes * 60) + set_seconds)

    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)
    logger.info(f"wait for {wait_time} seconds")
    time.sleep(wait_time)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec

    assert (time_dif - wait_time) == 0, "get time is not updated"

    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    logger.info("get IP through dhcp")
    ip_address = wifi_dut.interfaces.wifi.start_ip()

    set_seconds = 30
    set_minutes = 6
    set_hour = 10
    set_month_day = 10
    set_month = 10
    set_year = 2021
    set_week_day = 3
    wait_time = 100
    set_time_sec = ((set_minutes * 60) + set_seconds)

    # This API starts RTC timer in DUT
    wifi_dut.interfaces.wifi.set_rtc(seconds=set_seconds, minutes=set_minutes, hour=set_hour,
                                     month_day=set_month_day,
                                     month=set_month, year=set_year, week_day=set_week_day)
    time.sleep(wait_time)

    # get_rtc API returns time parameters output at the instance
    get_seconds, get_minutes, get_hours, get_day_month, get_month, get_year, get_week_day = wifi_dut.interfaces.wifi.get_rtc()
    get_time_sec = ((get_minutes * 60) + get_seconds)
    assert (set_hour == get_hours) and (set_month_day == get_day_month) and (set_month == get_month) and (
            set_year == get_year) and (set_week_day == get_week_day)

    time_dif = get_time_sec - set_time_sec

    assert (time_dif - wait_time) == 0, "get time is not updated"


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,

        },
    )
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['reset', 'init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
def test_query_dns_testcase48(wifi_dut, wifi_access_point, logger):
    wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
    time.sleep(2)
    logger.info("Connecting to the AP")
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    # DUT gets ipaddress through DHCP process after start_ip API is executed
    logger.info("get IP through dhcp")
    ip_address = wifi_dut.interfaces.wifi.start_ip()
    device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')

    logger.info(f"*****Enable Max PSP in DUT******")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger.info(f"DUT MAC_Address: {mac_address}")
    # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel}'
    # packet_filter2 = False
    wifi_dut.interfaces.wifi.power_save(2, 0)
    wifi_dut.interfaces.wifi.bt_power_save(
        power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
        )
    time.sleep(3)
    result = wifi_dut.interfaces.wifi.version()
    logger.info(f" DUT_Version: {result}")
    time.sleep(5)

    status = ping(device_ip, 10)
    assert status == 1
    result = wifi_dut.interfaces.wifi.dns_get(4, "www.google.com")
    logger.info(result.decode())
