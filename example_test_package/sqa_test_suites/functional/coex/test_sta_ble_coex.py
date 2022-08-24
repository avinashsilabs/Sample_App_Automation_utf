import time
import pytest
import random
import string
import datetime
from threading import Thread
from utf.utils.thread_base import ThreadBase
from utf.utils.time_measurer import TimeMeasurer
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116PowerSaveModes, RS9116AsyncEventType, \
    RS9116TCPIPFeatureBitMap, RS9116ExtCustomFeatureBitMap, RS9116FeatureBitMap, RS9116CustomFeatureBitMap, \
    RS9116BTFeatureBitMap, RS9116ExtTCPIPFeatureBitMap, RS9116ConfigFeatureBitMap, SocketOptions, SocketType, \
    RS9116PowerSaveProcedureTypes
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BLEDeviceState
from utf.interfaces.wifi import WlanError
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth.bluez.gatt_application.battery_service import BatteryService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.health_thermometer_service import HealthThermometerService
from utf.interfaces.bluetooth.bluetooth_logs import BleLogs
from utf.utils.stopwatch import Stopwatch
import threading

iperf_started = False
ping_count = 30
lock = threading.RLock()


def logger():
    return get_logger(__name__)


"""
    Setup Requirement: DUT(RS9116) , EFR32, 2 Raspberry PI required [ 2 BLE CLIENTS],
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by cg team, rashmi
    Description:Sta_ble_coex Test cases
"""


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def wifi_join(wifi_dut, wifi_access_point):
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_fail = 1
    for count in range(1, 4):
        try:
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            ip_fail = 0
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(1)
    assert ip_fail == 0, "ip setting in DUT has failed"

    wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                        RS9116PowerSaveProcedureTypes.FastPowerSave)
    wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                           RS9116PowerSaveProcedureTypes.FastPowerSave)

    logger().info(f'DUT ip {device_ip}')
    logger().info("pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")
    time.sleep(10)
    return device_ip


def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True,
                     expected="RSI_BLE_ENCRYPT_STARTED_EVENT",
                     skip_scan=False):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        if start_needed:
            logger().info(f"Set up DUT for BLE master role")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            logger().info("Started BLE in DUT")
            assert ble_dut_address, f"Unable to fetch ble dut address"
        logger().info("Start ble client")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, "Unable to get ble_client_address"
        time.sleep(5)
        if not skip_scan:
            logger().info("Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
            wifi_dut.interfaces.wifi.ble_stop_scanning()
        time.sleep(5)
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected, timeout=120)
        logger().info("BLE Connection success")

    if mode == "ble_slave":
        if start_needed:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to find ble dut address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[
                    wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info("BLE Connection success")
        time.sleep(2)
    return ble_client_address, ble_dut_address


def verify_sniffer_validation(wifi_sniffer, dut_mac_address, bssid):
    validation = True
    # validate PS-POLL frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x001a) and (wlan.ta == {dut_mac_address}) ' \
                     f'and (wlan.ra == {bssid}))'

    # validate QOS data frame with more data bit set to '1'
    packet_filter2 = f' (wlan.fc.moredata == 1) and ((wlan.fc.type_subtype == 0x0028) and (wlan.ra == {dut_mac_address}) ' \
                     f'and (wlan.ta == {bssid}))'

    logger().info('Validating PS Poll frames are sent from the device with power management bit')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for ps-poll frame with PM bit 1'

    logger().info('Validating more data bit in QOS data frames')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Sniffer validation failed for QOS data frame with more data bit 1'


def ble_disconnect(wifi_dut, ble_address):
    # Ble disconnect
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_address, timeout=30)
    # ble_client.interfaces.bluetooth.disconnect(ble_address)
    time.sleep(3)
    logger().info("Successfully disconnected from BLE SLAVE Device")


def wifi_leave(wifi_dut):
    with TimeMeasurer() as t:
        wifi_dut.interfaces.wifi.leave(timeout=60)
    logger().info(f"Leave completed in {t.duration} seconds")


def run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
    logger().info("Getting Host IP address")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    global iperf_started
    iperf_started = True
    net_perf_client.interfaces.net_perf.start()
    # open socket and send traffic

    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )

    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        print_dict("##     ", iperf_throughput)
        logger().info("Iperf throughput printed successfully")


def check_connection_status(wifi_dut, bt=False, ble=False, wlan=False):
    if ble:
        logger().info("Checking connection status of BLE")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to BLE"
        logger().info("DUT is not disconnected from BLE")

    if wlan:
        logger().info("Checking connection status of Wi-Fi")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, f"DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0
        logger().info(f"DUT is not disconnected from Wi-Fi during traffic run for long duration")


def connect_disconnect_ble(wifi_dut, ble_client, ble_client_address, ble_dut_address=None, mode=None, iter_count=5,
                           expected="RSI_BLE_ENCRYPT_STARTED_EVENT",
                           skip_scan=False):
    error = False
    wait_time = 0
    expected = expected
    while True:
        if iperf_started:
            break
        elif wait_time == 20:
            error = True
            break
        else:
            time.sleep(10)
            wait_time += 1

    if error:
        logger().warning("Iperf did not start after long wait...can not proceed with bt_connect_disconnect")
        assert iperf_started is True, "Iperf did not start after long wait...can not proceed with " \
                                      "ble_connect_disconnect "

    for i in range(1, iter_count + 1):

        if mode == "ble_slave":
            logger().info(f"slave mode")
            logger().info(f"Initiating BLE disconnection...iteration: '{i}'")
            ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
            # wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)
            logger().info(f"RASPI Disconnect completed...iteration: '{i}'")
            time.sleep(3)
            logger().info(f"RASPI Re-Initiating BLE slave connection...iteration: '{i}'")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f"Unable to fetch MAC address from DUT"
            wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            ble_client.interfaces.bluetooth.close()
            time.sleep(3)
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"ble client address not found"
            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_scanning()
            logger().info(f"See that we found our device")
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            assert wifi_dut.interfaces.wifi.ble_address in found_devices
            assert (
                    found_devices[wifi_dut.interfaces.wifi.ble_address]
                    == wifi_dut.interfaces.wifi.ble_advertising_data
            )

            ble_client.interfaces.bluetooth.connect(ble_dut_address)
            logger().info(f"DUT successfully connected to {ble_client} Device...iteration: '{i}'")
            time.sleep(3)

        if mode == "ble_master":
            logger().info("master mode")
            logger().info(f"Initiating BLE disconnection...iteration: '{i}'")
            wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)
            logger().info(f"DUT Disconnect completed ...iteration: '{i}'")
            time.sleep(3)
            logger().info(f"Re-Initiating BLE master connection...iteration: '{i}'")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, "Unable to get ble_client_address1"
            logger().info("Start ble client")
            ble_client.interfaces.bluetooth.close()
            time.sleep(3)
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, "Unable to get ble_client_address"
            time.sleep(3)
            if not skip_scan:
                logger().info("Start scanning and connect to ble client")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=80)
                wifi_dut.interfaces.wifi.ble_stop_scanning()
                time.sleep(3)
            logger().info("Initiating BLE connection with ble_client")
            wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=150,
                                                 expected=expected)
            logger().info("BLE Connection success")
            time.sleep(3)


class ble_master_slave_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode, disconnect=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT",
                 skip_scan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode
        self.disconnect = disconnect
        self.expected = expected
        self.skip_scan = skip_scan

    def run(self):
        ble_client_address, ble_dut_address = ble_master_slave(self.wifi_dut, self.ble_client, self.mode,
                                                               expected=self.expected,
                                                               skip_scan=self.skip_scan)
        if self.disconnect:
            time.sleep(3)
            logger().info("Disconnect method starts...")
            ble_disconnect(self.wifi_dut, ble_client_address)
        return ble_client_address, ble_dut_address


class ble_slave_advertise_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode, disconnect=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT",
                 skip_scan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.mode = mode
        self.disconnect = disconnect
        self.expected = expected
        self.skip_scan = skip_scan

    def run(self):
        logger().info(f"Set up DUT for BLE advertising")
        ble_dut_address = self.wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to find ble dut address"

        self.wifi_dut.interfaces.wifi.ble_start_advertising()
        logger().info(f"Begin Scanning for BLE devices")
        self.ble_client.interfaces.bluetooth.close()
        time.sleep(3)
        ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"ble client address not found"
        time.sleep(5)
        self.ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = self.ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert self.wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[
                    self.wifi_dut.interfaces.wifi.ble_address] == self.wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
        if self.disconnect:
            time.sleep(3)
            logger().info("Disconnect method starts...")
            ble_disconnect(self.wifi_dut, ble_client_address)
        return ble_client_address, ble_dut_address


class wifi_join_thread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        with TimeMeasurer() as t:
            scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=None)
        logger().info(scan_results)
        assert len(scan_results) > 0, f"scan_list not found"
        logger().info(f"Scan in {t.duration} seconds")
        logger().info("Joining into Wi-Fi")
        wifi_join(self.wifi_dut, self.wifi_access_point)


class wifi_negative_scan_thread(ThreadBase):
    def __init__(self, wifi_dut, ssid):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssid = ssid

    def run(self):
        with pytest.raises(WlanError) as exc_info:
            scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=self.ssid, retries=15)
            logger().info(scan_results)
        assert exc_info.value.error_code == 0x3, "DUT sent wrong error code for scan fail, expected is 0x3"
        logger().info("STA scan mode completed")
        logger().info("wifi_negative_scan_thread thread completed")


class wifi_scan_thread(ThreadBase):
    def __init__(self, wifi_dut, ssid=None, scan_count=5):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ssid = ssid
        self.scan_count = scan_count

    def run(self):
        for i in range(1, self.scan_count + 1):
            scan_results = self.wifi_dut.interfaces.wifi.scan(ssid=self.ssid, timeout=30)
            logger().info(scan_results)
            logger().info(f"STA scan mode iteration:{i}")
            time.sleep(5)
        logger().info("wifi_scan_thread thread completed")


class ble_continuous_scan_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode, ble_scan_interval=100, ble_scan_window=5, ble_client_address=None,
                 ble_dut_address=None):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address
        self.mode = mode
        self.ble_scan_interval = int(ble_scan_interval / 0.625)
        self.ble_scan_window = int(ble_scan_window / 0.625)

    def run(self):
        self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address, \
                                                         ble_scan_interval=self.ble_scan_interval, \
                                                         ble_scan_window=self.ble_scan_window, timeout=120)
        logger().info("ble_continuous_scan_thread completed")


class ble_scan_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, mode, ble_client_address=None, ble_dut_address=None, scan_count=1):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address
        self.mode = mode
        self.scan_count = scan_count

    def run(self):
        for i in range(1, self.scan_count + 1):
            time.sleep(2)
            if self.mode == 'ble_slave':
                logger().info("Begin Scanning for DUT from ble_client")
                ble_client_address = self.ble_client.interfaces.bluetooth.start_smp_scan(
                    bt_dut_address=self.ble_dut_address)
                assert ble_client_address, "Unable to get ble_client_address"
                self.ble_client.interfaces.bluetooth.stop_scanning()
                logger().info("See that we found our device")
                logger().info("DUT is still being discovered by remote BLE device")
                time.sleep(5)
                self.ble_client.interfaces.bluetooth.close()
                time.sleep(5)
            else:
                logger().info(f"Start scanning for ble client")
                self.wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=self.ble_client_address,
                                                                 timeout=100)
                self.wifi_dut.interfaces.wifi.ble_stop_scanning()
                time.sleep(3)
                logger().info(f"Scanning success....iteration:{i}")
        logger().info("ble_scan_thread completed")


class check_connection_status_thread(ThreadBase):
    def __init__(self, wifi_dut, bt=False, ble=False, wlan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.bt = bt
        self.ble = ble
        self.wlan = wlan

    def run(self):
        check_connection_status(self.wifi_dut, bt=self.bt, ble=self.ble, wlan=self.wlan)
        logger().info("check_connection_status_thread completed")


class wifi_traffic_thread(ThreadBase):
    def __init__(self, net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
        super().__init__()
        self.net_perf_client = net_perf_client
        self.wifi_dut = wifi_dut
        self.wifi_client = wifi_client
        self.protocol = protocol
        self.device_ip = device_ip
        self.iperf_time = iperf_time

    def run(self):
        run_iperf_server(self.net_perf_client, self.wifi_dut, self.wifi_client, self.protocol, self.device_ip,
                         self.iperf_time)
        logger().info("Wi-Fi traffic thread completed")


class connect_disconnect_wifi_thread(Thread):
    def __init__(self, wifi_dut, wifi_access_point, iter_count):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point
        self.iter_count = iter_count

    def run(self):
        # check whether iperf started before wifi-disconnect-connect
        error = False
        wait_time = 0
        while True:
            if iperf_started:
                break
            elif wait_time == 20:
                error = True
                break
            else:
                time.sleep(10)
                wait_time += 1

        if error:
            logger().warning("Iperf did not start after long wait...can not proceed with wifi_connect_disconnect")
            assert iperf_started is True, "Iperf did not start after long wait...can not proceed with " \
                                          "wifi_connect_disconnect "

        for i in range(1, self.iter_count + 1):
            time.sleep(5)
            logger().info(f"Initiating W-Fi disconnection on DUT...Iteration: '{i}'")
            wifi_leave(self.wifi_dut)
            logger().info(f"Successfully disconnected Wi-Fi from DUT...Iteration: '{i}'")
            time.sleep(2)
            logger().info(f"Re-Initiating W-Fi connection on DUT...Iteration: '{i}'")
            wifi_join(self.wifi_dut, self.wifi_access_point)
            logger().info(f"DUT successfully connected to Wi-Fi...Iteration: '{i}'")
        logger().info("Wi-Fi Connect-Disconnect thread completed")


class connect_disconnect_ble_master_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_client_address, ble_dut_address, mode, iter_count,
                 expected="RSI_BLE_MTU_EVENT",
                 skip_scan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address
        self.iter_count = iter_count
        self.mode = mode
        self.expected = expected
        self.skip_scan = skip_scan

    def run(self):
        connect_disconnect_ble(self.wifi_dut, self.ble_client, self.ble_client_address, self.ble_dut_address,
                                      self.mode, self.iter_count,
                                      expected=self.expected,
                                      skip_scan=self.skip_scan)

        logger().info("BLE master connect_disconnect_thread completed")


class connect_disconnect_ble_slave_thread(ThreadBase):
    def __init__(self, wifi_dut, ble_client, ble_client_address, ble_dut_address, mode, iter_count,
                 expected="RSI_BLE_MTU_EVENT",
                 skip_scan=False):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.ble_client = ble_client
        self.ble_client_address = ble_client_address
        self.ble_dut_address = ble_dut_address
        self.iter_count = iter_count
        self.mode = mode
        self.expected = expected
        self.skip_scan = skip_scan

    def run(self):
        connect_disconnect_ble(self.wifi_dut, self.ble_client, self.ble_client_address, self.ble_dut_address, self.mode,
                               self.iter_count,
                               expected=self.expected,
                               skip_scan=self.skip_scan)

        logger().info("BLE slave connect_disconnect_thread completed")


class stop_ap_thread(ThreadBase):
    def __init__(self, wifi_dut, wifi_access_point):
        super().__init__()
        self.wifi_dut = wifi_dut
        self.wifi_access_point = wifi_access_point

    def run(self):
        # check whether iperf started before wifi-disconnect-connect
        error = False
        wait_time = 0
        while True:
            if iperf_started:
                break
            elif wait_time == 20:
                error = True
                break
            else:
                time.sleep(10)
                wait_time += 1

        if error:
            logger().warning("Iperf did not start after long wait...can not proceed with stop AP")
            assert iperf_started is True, "Iperf did not start after long wait...can not proceed with stop AP"

        self.wifi_access_point.interfaces.wifi.stop_ap()
        logger().info("stop_ap thread completed")


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20324'})
@pytest.mark.parametrize("ssid", ['test_C20324'])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_get_local_bd_address_of_ble_while_sta_data_transfer_inprogress_C20324(wifi_dut, bt_dut, wifi_access_point,
                                                                               net_perf_client, wifi_client,
                                              ble_client, protocol, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    bt_local_name = "rs911x_bt_spp"

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, "scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Device ip fetch failed"

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    logger().info("starting bt module in dut.....")
    bt_dut.interfaces.bluetooth.bt_start()

    logger().info("fetching dut bd address....")
    bd_dut_address = bt_dut.interfaces.bluetooth.bt_get_local_address()

    logger().info("configuring bt name....")
    bt_dut.interfaces.bluetooth.bt_set_local_name(bt_local_name)

    logger().info("fetching dut bd name....")
    bd_local_name = wifi_dut.interfaces.wifi.bt_get_local_name()

    logger().info(f"DUT local BD address: '{bd_dut_address}'")
    logger().info(f"DUT local BD name: '{bd_local_name}'")

    # ble_mode = "ble_slave"
    ble_mode = "ble_master"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client, ble_mode)

    t1.wait_for_exit(True)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'C20310'})
@pytest.mark.parametrize("ssid", ['C20310'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_connection_stability_of_rsi_sta_when_ble_dual_role_C20310(wifi_dut, bt_dut, ble_clients, wifi_access_point,
                                                                   ssid, net_perf_client, wifi_client, wifi_sniffer,
                                                                   protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    validation = True
    iter_count = 5
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C20310.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    assert len(ble_clients) >= 2
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Device IP fetching failed"

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address1 = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    time.sleep(5)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address2, ble_dut_address2 = ble_master_slave(wifi_dut, ble_client2, ble_mode)

    logger().info(f"ble_client_address:{ble_client_address2}")
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t2 = connect_disconnect_ble_master_thread(wifi_dut, ble_client2, ble_client_address2, ble_dut_address2, "ble_master", iter_count=5, skip_scan=True)

    t1.start()
    logger().info("BLE master connect_disconnect_thread execution starts...")
    t2.start()
    logger().info("starting the second slave connect and disconnect...")
    connect_disconnect_ble(wifi_dut, ble_client1, ble_client_address1, ble_dut_address1, "ble_slave", iter_count=5)

    for i in range(1, iter_count + 1):
        logger().info(f"Checking connection status of wlan...iteration:{i}")
        check_connection_status(wifi_dut, wlan=True)
        time.sleep(10)

    t1.wait_for_exit(True)
    t2.wait_for_exit(True)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    verify_sniffer_validation(wifi_sniffer, dut_mac_address, bssid)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'adv_functionality_ble_C20111'})
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
    },
)
def test_adv_functionality_of_ble_when_sta_scan_C20311(wifi_dut, wifi_sniffer, wifi_access_point, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C20311.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    ble_mode = "ble_slave"
    with wifi_scan_thread(wifi_dut, scan_count=3), ble_slave_advertise_thread(wifi_dut, ble_client, ble_mode):
        time.sleep(15)
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = f"(wlan.fc.type_subtype == 0x0004) and (wlan.sa == {dut_mac_address} && wlan.da == " \
                     f"ff:ff:ff:ff:ff:ff) "
    logger().info(
        f"Validating Probe req(Broadcast)"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find Probe req(Broadcast) in sniffer'


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_adv_func_of_ble_while_sta_data_transfer_inprogressC20312(wifi_dut, ble_client, wifi_access_point,
                                                                 net_perf_client,
                                                          wifi_client, protocol, wifi_sniffer):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C20312.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info("ble_connection+wlan_traffic thread execution starts...")
    ble_mode = "ble_slave"
    with ble_slave_advertise_thread(wifi_dut, ble_client, ble_mode), wifi_traffic_thread(net_perf_client, wifi_dut,
                                                                                         wifi_client,
                                                                                         protocol, device_ip,
                                                                                         iperf_time=100):
        time.sleep(15)

    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20313'})
@pytest.mark.parametrize("ssid", ['test_C20313'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_adv_functionality_of_ble_when_sta_disconnect_C20313(wifi_dut, ble_client, wifi_access_point, net_perf_client,
                                                             wifi_client, protocol, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info("starting ble in DUT...")
    ble_mode = "ble_slave"
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, "Unable to get ble_client_address1"
    logger().info("Begin BLE Advertising on DUT")
    wifi_dut.interfaces.wifi.ble_start_advertising()
    logger().info("DUT is on BLE Advertising mode...")
    time.sleep(1)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)
    time.sleep(30)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("stop_ap+wifi_negative_scan thread execution starts...")
    with stop_ap_thread(wifi_dut, wifi_access_point), wifi_scan_thread(wifi_dut), ble_scan_thread(
            wifi_dut, ble_client, ble_mode, ble_dut_address, scan_count=5):
        time.sleep(15)
    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20315'})
@pytest.mark.parametrize("ssid", ['test_C20315'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
def test_functionality_of_sta_when_ble_scan_C20315(wifi_dut, ble_client, wifi_access_point, wifi_sniffer, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_Case_C20315.txt')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, skip_scan=True)

    t1 = wifi_join_thread(wifi_dut, wifi_access_point)
    t2 = ble_continuous_scan_thread(wifi_dut, ble_client, ble_mode, ble_scan_interval=100, ble_scan_window=5,
                         ble_client_address=ble_client_address)

    t1.start()
    time.sleep(20)
    t2.start()

    t1.wait_for_exit(True)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address)
    logger().info("Stop Sniffer finally")

    wifi_sniffer.interfaces.capture.stop_capture()
    verify_sniffer_validation(wifi_sniffer, dut_mac_address, bssid)


############### PR2 ####################################
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20314'})
@pytest.mark.parametrize("ssid", ['test_C20314'])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
def test_connectivity_of_ble_when_sta_connect_scan_disconnect_C20314(wifi_dut, ble_client, wifi_access_point, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    wifi_join(wifi_dut, wifi_access_point)

    ble_mode = "ble_slave"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"ble_address: '{ble_client_address}'")

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Checking connection status of BLE+wlan_scan thread execution starts...")
    t1 = wifi_scan_thread(wifi_dut, ssid, scan_count=10)
    t1.start()

    logger().info("Checking ble connection still persists")
    check_connection_status(wifi_dut, ble=True)

    t1.wait_for_exit()
    logger().info("Initiating BLE disconnection from ble_client")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(3)

    wifi_dut.interfaces.wifi.bt_deinit()

    logger().info(f"Re-Initiating BLE connection with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info("DUT is scannable, connectable")

    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20319'})
@pytest.mark.parametrize("ssid", ['test_C20319'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_disconnect_request_of_ble_when_sta_scan_connect_and_disconnect_C20319(wifi_dut, ble_client, wifi_access_point,
                                                                 net_perf_client, wifi_client, protocol, ssid):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info("wlan_traffic+ble_connection thread execution starts...")
    ble_mode = "ble_master"

    t1 = ble_master_slave_thread(wifi_dut, ble_client, ble_mode)
    t2 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)
    t1.start()
    time.sleep(10)
    t2.start()
    t1.wait_for_exit(True)
    t2.wait_for_exit(True)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    ble_client_address, _ = t1.return_value
    logger().info(f"ble_client_address:{ble_client_address}")
    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address)

    logger().info("wlan_scan+ble_connection thread execution starts...")
    with wifi_scan_thread(wifi_dut, ssid, scan_count=3), ble_master_slave_thread(wifi_dut, ble_client, ble_mode,
                                                                                 disconnect=True,
                                                                                 expected="RSI_BLE_MTU_EVENT",
                                                                                 skip_scan=False):
        time.sleep(15)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20320'})
@pytest.mark.parametrize("ssid", ['test_C20320'])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_Active_scan_func_of_ble_when_sta_connect_C20320(wifi_dut, ble_client, wifi_access_point, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    wifi_join(wifi_dut, wifi_access_point)

    logger().info("starting ble in DUT...")
    ble_mode = "ble_master"
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    logger().info(f"Started BLE in DUT")
    assert ble_dut_address, "Unable to get ble_dut_address"
    logger().info(f"Start ble client")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get ble_client_address"
    time.sleep(3)

    logger().info(f"Start scanning for ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=80)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    logger().info(f"Scanning success")

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("wlan+ble scan thread execution starts...")
    with wifi_scan_thread(wifi_dut, ssid, scan_count=5), ble_scan_thread(wifi_dut, ble_client, ble_mode,
                                                                         ble_client_address=ble_client_address,
                                                                         scan_count=2):
        time.sleep(15)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20328'})
@pytest.mark.parametrize("ssid", ['test_C20328'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_scan_enable_and_disable_func_of_ble_when_sta_connect_C20328(wifi_dut, ble_client, wifi_access_point,
                                                        net_perf_client, wifi_client, protocol, ssid):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info("starting ble in DUT...")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    logger().info(f"Started BLE in DUT")
    assert ble_dut_address, "Unable to get ble_dut_address"
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)
    logger().info("Advertise ble client for DUT master mode")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get ble_client_address"
    time.sleep(5)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    for i in range(1, 3):
        logger().info(f"Start scanning for ble client...iteration:{i}")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
        logger().info(f"Scanning success, we found our remote device...iteration:{i}")

        logger().info(f"Stop scanning on DUT...iteration:{i}")
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info(f"Stop scanning success...iteration:{i}")

    t1.wait_for_exit(True)
    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20329'})
@pytest.mark.parametrize("ssid", ['test_C20329'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_scan_adv_func_of_ble_while_sta_data_transfer_inprogress_C20329(wifi_dut, ble_client, wifi_access_point,
                                                            net_perf_client, wifi_client,protocol, ssid):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    logger().info("starting ble in DUT...")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    logger().info(f"Started BLE in DUT")
    assert ble_dut_address, "Unable to get ble_dut_address"

    logger().info("Advertise ble client for DUT master mode")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get ble_client_address"

    logger().info("Set up DUT for BLE advertising")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info("Start scanning for ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=80)
    logger().info("Scanning success, we found our remote device")

    logger().info("Begin Scanning for DUT from ble_client")
    ble_client.interfaces.bluetooth.close()
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, "Unable to get ble_client_address"
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info("See that we found our DUT")
    logger().info("DUT is being discovered by remote BLE device")

    t1.wait_for_exit(True)

    wifi_dut.interfaces.wifi.bt_deinit()
    wifi_dut.interfaces.wifi.ble_initialized = False
    ble_client.interfaces.bluetooth.close()


################## PR3 ###################################
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_dual_role_ble_msg_based_power_save_C20277(wifi_dut, ble_clients, wifi_access_point,
                                                   net_perf_client, wifi_client, wifi_sniffer, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='msg_based_power_save_C20277')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    time.sleep(2)

    ble_mode = "ble_master"
    logger().info(f"##### Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
    logger().info(f"*** BLE_MASTER CONNECTION SUCCESSFUL")

    ble_mode = "ble_slave"
    logger().info(f"++++ Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)
    logger().info(f"+++ BLE SLAVE CONNECTION SUCCESSFUL")

    time.sleep(15)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'

    logger().info("Checking connection status of BLE")
    check_connection_status(wifi_dut, ble=True)

    logger().info("Initiating BLE disconnection on DUT, since DUT is master")
    ble_disconnect(wifi_dut, ble_client_address1)
    logger().info("Initiating BLE disconnection from Raspi, since Raspberrypi is master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)

    time.sleep(2)
    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_dual_role_ble_gpio_based_power_save_C20279(wifi_dut, ble_clients, wifi_access_point,
                                                    net_perf_client, wifi_client, wifi_sniffer, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='gpio_based_power_save_C20279')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)

    logger().info("Setting gpio based power-save as True")
    wifi_dut.interfaces.wifi.set_sleep_gpio(True)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip)

    # validate NULL data frame with PM bit set to '1'
    packet_filter1 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {bssid}))'
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info('Validation for NULL packet with pm bit 1')
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Sniffer validation failed for NULL data frame with PM bit 1'

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address1)

    logger().info("Initiating BLE disconnection from Raspi, since Raspberrypi is master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)

    time.sleep(3)
    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20316'})
@pytest.mark.parametrize("ssid", ['test_C20316'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_connection_request_of_ble_when_sta_scan_connect_disconnect_state_C20316(wifi_dut, ble_clients,
                                wifi_access_point, net_perf_client,wifi_client, protocol, ssid):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan list is empty"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Device ip fetch failed"

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)
    t1.start()
    time.sleep(30)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client1, ble_mode)
    time.sleep(5)

    t1.wait_for_exit(True)

    logger().info("Initiating Wi-Fi disconnection on DUT")
    wifi_leave(wifi_dut)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address)
    time.sleep(10)

    logger().info("wlan_scan+ble_connection thread execution starts...")
    with wifi_scan_thread(wifi_dut, ssid, scan_count=5), ble_master_slave_thread(wifi_dut, ble_client1, ble_mode,
                                                                                 expected="RSI_BLE_MTU_EVENT",
                                                                                 skip_scan=True):
        time.sleep(15)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode)

    logger().info("Initiating BLE connection check on DUT")
    check_connection_status(wifi_dut, ble=True)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address)
    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20330'})
@pytest.mark.parametrize("ssid", ['test_C20330'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_disconnect_event_of_ble_while_sta_data_transfer_inprogress_C20330(wifi_dut, ble_client,
                                            wifi_access_point, net_perf_client, wifi_client, protocol, ssid):
    iter_count = 5
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"Scan list is empty"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    data = []
    for i in range(iter_count):
        data.append(text_generator(size=4))
    ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
    bt_local_name = "rs9116_test_C20330"
    logger().info("configuring bd local name....")
    wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name)

    logger().info("fetching bd local name....")
    bd_local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"bd local name is : {bd_local_name}")

    logger().info("start ble on DUT")
    ble_dut_addr = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_addr, "Unable to get ble_dut_addr"

    logger().info("Creating new custom gatt service in DUT")
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
    logger().info("Adding custom characteristic declaration to the custom service")
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
    logger().info("Adding characteristic value attribute to the service")
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[0])

    logger().info("Start ble client")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_addr)
    assert ble_client_address, "Unable to get ble_client_address"
    time.sleep(5)

    logger().info("Start scanning and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
    logger().info(f"See that we found our device")
    wifi_dut.interfaces.wifi.ble_stop_scanning()

    logger().info("Initiating BLE connection with ble_client")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120)
    logger().info("BLE Connection success")
    time.sleep(2)

    logger().info("Configuring remote device to receive notifications from DUT")
    service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
    char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
    bus = ble_client.interfaces.bluetooth.bus
    services, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
    assert len(services) > 0, "Unable to fetch services"
    assert len(chars) > 0, "Unable to get characteristics list from ble_client"

    char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus, services=services,
                                                                                           service_uid=service_uid,
                                                                                           char_uid=char_uid)
    assert char is not None, "Unable to resolve custom service characteristic from ble_client"
    assert len(char_props) > 0, "Unable to get char_props"

    logger().info("Subscribing to notifications on ble_client")
    ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
    ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)

    logger().info("Sending notifications from DUT")
    for i in range(iter_count):
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[i])
        wifi_dut.interfaces.wifi.ble_notify_value()

    logger().info("Validating received notifications on ble_client")
    notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
    logger().info(f"Notifications: {notifications}")
    notification_len = len(notifications)
    for i in range(0, notification_len):
        assert notifications[i] == data[i], "Received wrong data in ble_client"

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()
    time.sleep(15)

    logger().info(f"Checking connection status of wlan and BLE , both should be true")
    check_connection_status(wifi_dut, ble=True, wlan=True)

    logger().info("Issuing BLE disconnect from remote device")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_addr)
    time.sleep(10)

    logger().info("Now connection status - wlan should be connected and BLE should be disconnected")
    check_connection_status(wifi_dut, wlan=True)
    logger().info("Checking connection status of BLE")

    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert not state_int == BLEDeviceState.Connected
    logger().info("DUT is disconnected from BLE")

    t1.wait_for_exit(True)

    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config('wifi_access_point',
                    wifi={"ssid": "ssid_C20336", "passphrase": "12345567890", "security": "WPA2", "cipher": 'AES'})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_throughput_func_of_sta_when_ble_connect_C20336(wifi_dut, ble_clients, wifi_access_point,
                                            net_perf_client, wifi_client, wifi_sniffer, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='C20336_wpa2_dual_role')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Device ip fetch failed"

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)

    with wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip,
                             iperf_time=200), check_connection_status_thread(wifi_dut, ble=True, wlan=True):
        time.sleep(60)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address1)

    logger().info("Initiating BLE disconnection from Raspi, since Raspberrypi is master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)


############# PR4 #############################################

@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20333'})
@pytest.mark.parametrize("ssid", ['test_C20333'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
def test_dual_role_func_of_ble_while_sta_data_transfer_inprogress_C20333(wifi_dut, ble_clients, wifi_access_point,
                                                    net_perf_client,wifi_client, protocol, ssid):

    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, "Minimum 2 raspi required to run this test"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan list is empty"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    assert device_ip, "Device ip fetch failed"

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    _, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    logger().info("Initiating BLE connection check on DUT")
    check_connection_status(wifi_dut, ble=True)

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)

    logger().info("Initiating BLE connection check on DUT")
    check_connection_status(wifi_dut, ble=True)

    t1.wait_for_exit(True)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20334'})
@pytest.mark.parametrize("ssid", ['test_C20334'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_dual_role_func_of_ble_while_sta_data_transfer_inprogress_with_CI20ms_C20334(wifi_dut, ble_clients,
                                                             wifi_access_point, net_perf_client, wifi_client,

                                                protocol, ssid):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, "Minimum 2 raspi required to run this test"
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=wifi_access_point.interfaces.wifi.channel)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan list is empty"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    conn_params = {"min_conn_interval": 20,
                   "max_conn_interval": 20,
                   "conn_latency": 0,
                   "supervision_timeout": 200}

    logger().info("Initiating BLE test with 2 remote devices")
    logger().info("Start BLE in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, "Unable to fetch ble dut address"
    logger().info("Started BLE in DUT")

    # Configure 2 remote BLE devices in peripheral and central modes(RD1 in peripheral and RD2 in central).
    logger().info("Start ble_client1 for peripheral role")
    ble_client1.interfaces.bluetooth.close()
    ble_client_address1 = ble_client1.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
    assert ble_client_address1, "Unable to get ble_client_address1"
    logger().info("Start scanning for ble_client1")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address1, timeout=80)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    logger().info("Scan success for RD1")
    logger().info("Initiating BLE connection with ble_client1(RD1)")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address1,
                                         ble_conn_interval_min=conn_params["min_conn_interval"],
                                         ble_conn_interval_max=conn_params["max_conn_interval"],
                                         timeout=conn_params["supervision_timeout"])
    logger().info("BLE Connection with RD1 success")

    logger().info("Start ble_client2 for central role")
    ble_client2.interfaces.bluetooth.close()
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(3)
    logger().info(f"Begin Scanning for BLE devices")
    ble_client_address2 = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address2, "Unable to get ble_client_address"
    time.sleep(5)
    logger().info(f"See that we found our device")
    ble_client2.interfaces.bluetooth.stop_scanning()
    logger().info("Initiating BLE connection with ble_client2(RD2)")
    ble_client2.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                             min_conn_interval=conn_params["min_conn_interval"],
                                             max_conn_interval=conn_params["max_conn_interval"],
                                             conn_latency=conn_params["conn_latency"],
                                             supervision_timeout=conn_params["supervision_timeout"])
    logger().info("BLE Connection with RD2 success")

    logger().info("Initiating BLE connection check on DUT initiating waiting time of 60 seconds")
    time.sleep(60)
    check_connection_status(wifi_dut, ble=True)

    t1.wait_for_exit(True)
    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address1)
    ble_disconnect(wifi_dut, ble_client_address2)
    wifi_dut.interfaces.wifi.bt_deinit()


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_scan_func_of_ble_while_sta_data_transfer_inprogress_C20335(wifi_dut, ble_client, wifi_access_point,
                                              net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    logger().info("Started BLE in DUT")
    ble_dut_addr = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_addr, "Unable to fetch ble dut address"
    logger().info("Start ble client")
    ble_client.interfaces.bluetooth.close()
    time.sleep(2)
    ble_client_addr = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_addr)
    assert ble_client_addr, "Unable to fetch ble_client_address"
    logger().info("Start scanning for ble client")
    time.sleep(3)
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_addr, timeout=100)
    wifi_dut.interfaces.wifi.ble_stop_scanning()

    t1.wait_for_exit(True)
    logger().info("Checking connection status of Wi-Fi")
    check_connection_status(wifi_dut, wlan=True)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2'})
def test_sta_connection_with_ble_connect_disconnect_C20280(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    start_needed = True
    ble_dut_address = ''
    expected = "RSI_BLE_ENCRYPT_STARTED_EVENT"

    for i in range(1, 11):
        logger().info(f"Initiating test.....iteration:{i}")

        ble_mode = "ble_master"
        logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
        ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address,
                                                               start_needed=start_needed,
                                                               expected=expected)
        logger().info(f"ble_client_address: '{ble_client_address}'")

        validation = True
        ssid = wifi_access_point.interfaces.wifi.ssid
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_C20280.txt')

        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
            logger().info(scan_results)
            assert len(scan_results) > 0, "scan list is empty"
        logger().info(f"Scan in {t.duration} seconds")

        logger().info("Joining into Wi-Fi on DUT")
        wifi_join(wifi_dut, wifi_access_point)

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        # QOS data Packets should be observed with More data Bit set to 1
        packet_filter1 = f'wlan.ta == {bssid} && wlan.da == {dut_mac_address} && wlan.fc.moredata==1'

        # PS Polls with Power Management Bit set to 1 should be sent from the device
        packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

        time.sleep(2)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating QOS data Packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find QOS data Packets'

        logger().info("Validating PS Polls with Power Management Bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find PS Polls with Power Management Bit'

        logger().info("Initiating BLE disconnection on DUT")
        ble_disconnect(wifi_dut, ble_client_address)

        logger().info("Initiating Wi-Fi disconnection on DUT")
        wifi_leave(wifi_dut)
        time.sleep(5)

        start_needed = False
        expected = "RSI_BLE_MTU_EVENT"
        logger().info(f"Iteration '{i}' completed")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_smp_func_of_ble_while_sta_data_transfer_inprogress_C20325(wifi_dut, ble_client, wifi_access_point,
                                                                   net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ssid = wifi_access_point.interfaces.wifi.ssid
    channel = wifi_access_point.interfaces.wifi.channel
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    logger().info(f"Set up DUT for BLE advertising")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"Unable to find ble dut address"
    wifi_dut.interfaces.wifi.ble_start_advertising()
    logger().info(f"Begin Scanning for BLE devices")
    ble_client.interfaces.bluetooth.close()
    time.sleep(3)
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address, f"ble client address not found"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()
    logger().info(f"See that we found our device")
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert wifi_dut.interfaces.wifi.ble_address in found_devices
    assert (
            found_devices[wifi_dut.interfaces.wifi.ble_address]
            == wifi_dut.interfaces.wifi.ble_advertising_data
    )

    # instead of ble_connect adding ble_pair and connect for secure connection
    logger().info("Connect to the dut with mac address..")

    connect_time = datetime.datetime.now()
    connect_state = ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_address)
    logger().info(f"connect_time  {connect_time}")
    assert connect_state, "unable to connect to the given address"
    time.sleep(30)

    logger().info("BLE Connection success")
    time.sleep(2)

    t1.wait_for_exit(True)
    logger().info("Checking connection status of BLE")
    check_connection_status(wifi_dut, ble=True)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address)


########################### PR5 ##################################

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_get_all_profiles_functionality_of_dut_ble_C20317(wifi_dut, ble_client, wifi_access_point,
                                                          net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ssid = wifi_access_point.interfaces.wifi.ssid
    channel = wifi_access_point.interfaces.wifi.channel
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30)
    t1.start()

    logger().info("start ble GATT service in DUT")
    ble_dut_addr = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert ble_dut_addr, "Unable to get ble_dut_addr"

    logger().info("Start ble client")
    ble_client.interfaces.bluetooth.close()
    time.sleep(2)
    service_classes = [BatteryService, HeartRateService, HealthThermometerService]
    ble_client_addr = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_addr,
                                                                    service_classes=service_classes)
    assert ble_client_addr, "Unable to get ble_client_addr"

    logger().info("Start scanning and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_addr, timeout=120)
    wifi_dut.interfaces.wifi.ble_stop_scanning()

    logger().info(f"Initiating connection this can take some time...")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_addr, timeout=120,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    logger().info("Checking connection status of BLE")
    check_connection_status(wifi_dut, ble=True)

    logger().info("Fetching all the configured profiles from RD1")
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_addr, timeout=30)
    logger().info(f"profiles uuid's are: {uuids}")

    uuid_dict = {"0x180f": "BatteryService", "0x180d": "HeartRateService", "0x1809": "HealthThermometerService"}
    uuid_list = [BatteryService.UUID, HeartRateService.UUID, HealthThermometerService.UUID]
    for uuid in uuid_list:
        uuid = uuid.lower()
        assert uuid in uuids, f"Unable to get '{uuid_dict[uuid]}' profile from RD1"
    logger().info(f"Successfully fetched all the profiles from RD1")

    t1.wait_for_exit(True)
    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_addr)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_get_particular_profiles_functionality_of_dut_ble_C20318(wifi_dut, ble_client, wifi_access_point,
                                                                 net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ssid = wifi_access_point.interfaces.wifi.ssid
    channel = wifi_access_point.interfaces.wifi.channel
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30)
    t1.start()

    logger().info("start ble GATT service in DUT")
    ble_dut_addr = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert ble_dut_addr, "Unable to get ble_dut_addr"

    logger().info("Start ble client")
    ble_client.interfaces.bluetooth.close()
    time.sleep(2)
    service_classes = [BatteryService, HeartRateService, HealthThermometerService]
    ble_client_addr = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_addr,
                                                                    service_classes=service_classes)
    assert ble_client_addr, "Unable to get ble_client_addr"

    logger().info("Start scanning and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_addr, timeout=120)
    wifi_dut.interfaces.wifi.ble_stop_scanning()

    logger().info(f"Initiating connection this can take some time...")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_addr, timeout=120,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    logger().info("Checking connection status of BLE")
    check_connection_status(wifi_dut, ble=True)

    logger().info("Fetching BatteryService profile from RD1")
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_addr, timeout=30)
    assert BatteryService.UUID in uuids is not None, "Unable to get BatteryService profile from RD1"
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=ble_client_addr,
                                                                              uuid=int(BatteryService.UUID, 16))
    assert start_handle is not None, "Unable to fetch the RD1 address"
    assert end_handle is not None, "Unable to get BatteryService profile from RD1"
    logger().info("Successfully fetched BatteryService profile from RD1")

    t1.wait_for_exit(True)
    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_addr)


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_ble_and_Wlan_data_transfer_for_5min_C20309(wifi_dut, ble_client, wifi_access_point, wifi_sniffer,
                                           net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    for iteration in range(1, 11):
        logger().info(f"Initiating test.....iteration:{iteration}")

        validation = True
        ssid = wifi_access_point.interfaces.wifi.ssid
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_C20309')

        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
        logger().info(scan_results)
        assert len(scan_results) > 0, f"scan_list not found"
        logger().info(f"Scan in {t.duration} seconds")

        logger().info("Joining into Wi-Fi")
        device_ip = wifi_join(wifi_dut, wifi_access_point)
        assert device_ip, "Device ip fetch failed"

        data = []
        for i in range(5):
            data.append(text_generator(size=4))
        ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        bt_local_name = "rs9116_test_C20309"
        logger().info("configuring bd local name....")
        wifi_dut.interfaces.wifi.bt_set_local_name(bt_local_name)

        logger().info("fetching bd local name....")
        bd_local_name = wifi_dut.interfaces.wifi.bt_get_local_name()
        logger().info(f"bd local name is : {bd_local_name}")

        logger().info("start ble on DUT")
        ble_dut_addr = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_addr, "Unable to get ble_dut_address"

        logger().info("Creating new custom gatt service in DUT")
        wifi_dut.interfaces.wifi.ble_add_service(uid=0x6E)
        logger().info("Adding custom characteristic declaration to the custom service")
        wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x6F)
        logger().info("Adding characteristic value attribute to the service")
        wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[0])

        logger().info("Start ble advertising on DUT")
        # 256(0x100), 512(0x200), 7(0x07)
        wifi_dut.interfaces.wifi.ble_start_advertising(ble_adv_int_min=256, ble_adv_int_max=512, ble_adv_channel_map=7)

        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        time.sleep(2)

        ble_client_addr = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_addr)
        assert ble_client_addr, "ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        logger().info(f"See that we found our device")
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert wifi_dut.interfaces.wifi.ble_address in found_devices
        assert (found_devices[wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data)

        connect_time = datetime.datetime.now()
        connect_state = ble_client.interfaces.bluetooth.pair_and_connect(ble_dut_addr, timeout=500)
        logger().info(f"connect_time  {connect_time}")
        assert connect_state, "unable to connect to the given address"

        logger().info("BLE Connection success")
        time.sleep(2)

        logger().info("Configuring remote device to receive notifications from DUT")
        service_uid = "0000006e-0000-1000-8000-00805f9b34fb"
        char_uid = "0000006f-0000-1000-8000-00805f9b34fb"
        bus = ble_client.interfaces.bluetooth.bus
        services, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics(bus)
        assert len(services) > 0, "Unable to fetch services"
        assert len(chars) > 0, "Unable to get characteristics list from ble_client"

        char, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(bus, services=services,
                                                                                               service_uid=service_uid,
                                                                                               char_uid=char_uid)
        assert char is not None, "Unable to resolve custom service characteristic from ble_client"
        assert len(char_props) > 0, "Unable to get char_props"

        logger().info("Subscribing to notifications on ble_client")
        ble_client.interfaces.bluetooth.gatt_adapter.enable_notifications(characteristic=char)
        ble_client.interfaces.bluetooth.gatt_adapter.subscribe_to_notifications(characteristic=char, char_uid=char_uid)

        logger().info("Sending notifications from DUT")
        for i in range(5):
            wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x6F, data=data[i])
            wifi_dut.interfaces.wifi.ble_notify_value()

        logger().info("Validating received notifications on ble_client")
        notifications = ble_client.interfaces.bluetooth.gatt_adapter.notifications[char_uid]
        logger().info(f"Notifications: {notifications}")
        notification_len = len(notifications)
        for i in range(0, notification_len):
            assert notifications[i] == data[i], "Received wrong data in ble_client"

        bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {bssid}')
        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")

        logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
        t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30)
        t1.start()

        t1.wait_for_exit(True)
        logger().info("Checking connection status of BLE")
        check_connection_status(wifi_dut, ble=True)

        with pytest.raises(Exception) as exc_info:
            logger().info("Initiating Wi-Fi disconnection on DUT")
            wifi_leave(wifi_dut)
            raise exc_info
        error_code = '0xffffffd5'
        if error_code in str(exc_info.value).lower() or iteration == 5:
            wifi_dut.interfaces.wifi.reset()
            time.sleep(2)
            wifi_dut.interfaces.wifi.init()

        # QOS data Packets should be observed with More data Bit set to 1
        packet_filter1 = f'wlan.ta == {bssid} && wlan.da == {dut_mac_address} && wlan.fc.moredata==1'

        # PS Polls with Power Management Bit set to 1 should be sent from the device
        packet_filter2 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

        time.sleep(2)
        logger().info("Stop Sniffer finally")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info("Validating QOS data Packets")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
            'packet_count'], 'Unable to find QOS data Packets'

        logger().info("Validating PS Polls with Power Management Bit")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
            'packet_count'], 'Unable to find PS Polls with Power Management Bit set to 1'

        logger().info("Initiating BLE disconnection from raspi")
        ble_client.interfaces.bluetooth.disconnect(ble_dut_addr)

        data.clear()
        ble_client.interfaces.bluetooth.gatt_adapter.notifications.clear()
        time.sleep(3)
        logger().info(f"Iteration '{iteration}' completed")


@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.config(
    "wifi_dut",
    "net_perf_client",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
    net_perf={"host_role": IperfConstants.SERVER_MODE},
)
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_query_rssi_of_ble_while_sta_data_transfer_inprogress_C20323(wifi_dut, ble_client, wifi_access_point,
                                                    net_perf_client, wifi_client, protocol):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    # global ble_dut_address

    ssid = wifi_access_point.interfaces.wifi.ssid
    channel = wifi_access_point.interfaces.wifi.channel
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
    logger().info(scan_results)
    assert len(scan_results) > 0, f"scan_list not found"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info(f"Initiating {protocol} traffic with client '{wifi_client.name}'")
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)
    time.sleep(3)

    # Jira to be resolved to enable the below section
    # https://jira.silabs.com/browse/UTF-1343
    # logger().info("Issuing rssi query from raspi device")
    # result = ble_client.interfaces.bluetooth.get_rssi(dev_addr=ble_dut_address)
    # logger().info(f"Result of rssi query from remote device is: {result}")

    # Check if DUT(BLE) device is able to issue RSSI query and getting response for the same from remote BLE device.
    logger().info("Issuing rssi query from DUT")
    result = wifi_dut.interfaces.wifi.bt_get_rssi(bt_remote_dev_address=ble_client_address)
    logger().info(f"Result of rssi query from DUT is: {result}")

    t1.wait_for_exit(True)
    logger().info("Checking connection status of BLE")
    check_connection_status(wifi_dut, ble=True)

    logger().info("Initiating BLE disconnection on DUT")
    ble_disconnect(wifi_dut, ble_client_address)


# =====================================================================================

@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
    },
)
@pytest.mark.config('wifi_access_point', wifi={"security": 'WPA2', "passphrase": '1234567890', "ssid": 'SILABS_AP'})
def test_sta_ble_connection_with_ble_connect_disconnect_C20246(wifi_dut, ble_client, wifi_access_point, wifi_sniffer):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    start_needed = True
    ble_dut_address = ''
    set_local_name = "SILICON_DEVICE_123"

    logger().info(f"Setting BLE local name {set_local_name}")
    wifi_dut.interfaces.wifi.bt_set_local_name(set_local_name)
    status = wifi_dut.interfaces.wifi.bt_get_local_name()
    logger().info(f"getting the local name : {status}")
    assert set_local_name == status, "Set local name and get local name not matched "

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode, ble_dut_address,
                                                           start_needed)
    logger().info(f"ble_client_address: '{ble_client_address}'")

    validation = True
    ssid = wifi_access_point.interfaces.wifi.ssid
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_case_C20246.txt')

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=ssid, channel=channel)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan list is empty"
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    # Checking association request or eapol
    packet_filter1 = f"wlan.addr=={dut_mac_address} && wlan.fc.type_subtype == 0 ||eapol"

    # Checking association response or eapol
    packet_filter2 = f"wlan.addr=={bssid} && wlan.fc.type_subtype == 1 ||eapol"

    # QOS data Packets should be observed with More data Bit set to 1
    packet_filter3 = f'wlan.ta == {bssid} && wlan.da == {dut_mac_address} && wlan.fc.moredata==1'

    # PS Polls with Power Management Bit set to 1 should be sent from the device
    packet_filter4 = f'(wlan.ta == {dut_mac_address}) and (wlan.fc.type_subtype == 0x001a)'

    time.sleep(2)
    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    logger().info(
        f"Validating association, eapol from DUT"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find association, eapol sent from DUT in sniffer '

    logger().info(
        f"Validating association, eapol from AP"
    )
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association, eapol sent from AP in sniffer '

    logger().info("Validating QOS data Packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find QOS data Packets'

    logger().info("Validating PS Polls with Power Management Bit")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with Power Management Bit'

    # Initiate ping from third party wifi-client to DUT
    logger().info(f'DUT ip {device_ip}')
    logger().info(f"pinging to dut.....")
    status = ping(device_ip, ping_count)
    assert status == 1, "DUT not responding for ping request......"
    logger().info(f"ping to DUT is successful....")

    logger().info("Initiating BLE connect and disconnect on DUT for 5 iterations")
    for i in range(1, 6):
        logger().info(f"Initiating BLE disconnection...iteration: '{i}'")
        ble_disconnect(wifi_dut, ble_client_address)
        logger().info(f"Disconnect completed...iteration: '{i}'")
        time.sleep(3)
        logger().info(f"Re-Initiating BLE connection...iteration: '{i}'")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
        assert ble_dut_address, f"Unable to get ble_dut_address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        ble_client.interfaces.bluetooth.connect(ble_dut_address)
        logger().info(f"DUT successfully connected to {ble_client} Device...iteration: '{i}'")
        time.sleep(3)

    wifi_leave(wifi_dut)
    time.sleep(5)
