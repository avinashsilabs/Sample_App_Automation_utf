import time
import pytest
import random
import string
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
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import BodySensorLocationCharacteristic
from utf.utils.stopwatch import Stopwatch

iperf_started = False
ping_count = 30


def logger():
    return get_logger(__name__)


"""
    Setup Requirement: DUT(RS9116) , EFR32, 2 Raspberry PI required [ 2 BLE CLIENTS],
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by cg team:  rashmi & team
    Description:Sta_ble_coex_basic_functionality Test cases
"""


def text_generator(size=200):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


def wifi_join(wifi_dut, wifi_access_point):
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_fail = 1
    for count in range(3):
        try:
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            ip_fail = 0
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count+1}")
            time.sleep(1)
    assert ip_fail == 0, "ip setting in DUT has failed"
    logger().info(f'DUT ip {device_ip}')

    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    time.sleep(15)
    for count in range(3):
        try:
            logger().info("pinging to dut.....")
            status = ping(device_ip, ping_count)
            assert status == 1, "DUT not responding for ping request......"
            logger().info("ping to DUT is successful....")
            break
        except:
            logger().info(f"DUT not responding for ping request..retry count -> {count + 1}")
            time.sleep(1)
    return device_ip


def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True, skip_scan=False,
                     secure_connect=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT", ):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        if start_needed:
            logger().info(f"Set up DUT for BLE master role")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            logger().info("Started BLE in DUT")
            assert ble_dut_address, f"ble_start failed , Unable to fetch ble dut address"
        logger().info("Start ble client")
        ble_client.interfaces.bluetooth.close()
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"failed to initiate ble in remote device, Unable to fetch ble_client_address"
        time.sleep(5)
        if not skip_scan:
            logger().info("Start scanning and connect to ble client")
            wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=80)
            wifi_dut.interfaces.wifi.ble_stop_scanning()
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected, timeout=120)
        time.sleep(2)
        logger().info("BLE Master Connection Success")

    if mode == "ble_slave":
        if start_needed:
            logger().info(f"Set up DUT for BLE advertising")
            ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
            assert ble_dut_address, f" failed to initiate ble in DUT, Unable to find ble dut address"
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(5)
        logger().info(f"Begin Scanning for BLE devices")
        ble_client.interfaces.bluetooth.close()
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address, f"failed to initiate ble in remote device,ble client address not found"
        time.sleep(5)
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices, "Could not able to find our DUT"
        assert (found_devices[
                    wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
        time.sleep(2)
        if secure_connect:
            ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=ble_dut_address)
        else:
            ble_client.interfaces.bluetooth.connect(ble_dut_address)
            time.sleep(2)
            logger().info("BLE Slave Connection Success")
    return ble_client_address, ble_dut_address


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
    time.sleep(5)
    # open socket and send traffic
    wifi_dut.interfaces.wifi.send_traffic_from_device(
        host_ip,
        device_ip,
        net_perf_client.interfaces.net_perf.server_port,
        net_perf_client.interfaces.net_perf.protocol,
        net_perf_client.interfaces.net_perf.client_options,
    )
    time.sleep(30)
    # get and print throughput
    tp = net_perf_client.interfaces.net_perf.process_output()
    assert tp is not None
    __print_throughput(tp)


def __print_throughput(iperf_throughput: dict):
    if iperf_throughput is not None:
        time.sleep(5)
        print_dict("##     ", iperf_throughput)
        logger().info("Iperf throughput printed successfully")


def check_connection_status(wifi_dut, ble=False, wlan=False):
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


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_ble_encryption_C20194(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client, ble_client,
                               protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_encryption_C20194"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    ble_mode = "ble_master"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    _, ble_dut_addr = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info("Checking connection status after 60 seconds")
    time.sleep(60)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    logger().info("Initiating BLE disconnection from remote device as per test plan")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_addr)

    ble_client.interfaces.bluetooth.close()
    time.sleep(3)
    logger().info("Advertising ble_client again as per test plan")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_addr)
    assert ble_client_address, "Unable to get ble_client_address"
    time.sleep(5)
    logger().info("Start scanning and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
    wifi_dut.interfaces.wifi.ble_stop_scanning()
    logger().info("Again Initiating BLE connection with ble_client")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected="RSI_BLE_MTU_EVENT",
                                         timeout=120)
    logger().info("BLE Connection success")
    t1.wait_for_exit(True)

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    # Validate dhcp packets in sniffer
    packet_filter5 = f'(dhcp) && (wlan.addr == {ap_bssid}) && (wlan.addr == {dut_mac_address})'

    port = net_perf_client.interfaces.net_perf.server_port
    logger().info(f"Port:{port}")
    packet_filter6 = f'udp.port eq {port}'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'

    # logger().info("Validating dhcp packets in sniffer")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
    #     'packet_count'], 'Unable to find dhcp packets'

    # logger().info("Validating udp packet")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
    #     'packet_count'], 'Unable to find udp packet'

    logger().info("Initiating BLE disconnection from DUT")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_ble_smp_pair_request_C20195(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client,
                                     ble_client, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_smp_pair_request_C20195"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(5)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    ble_mode = "ble_master"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_addr, ble_dut_addr = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status after 60 seconds")
    time.sleep(60)
    check_connection_status(wifi_dut, ble=True, wlan=True)
    t1.wait_for_exit(True)

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    # Validate dhcp packets in sniffer
    packet_filter5 = f'(dhcp) && (wlan.addr == {ap_bssid}) && (wlan.addr == {dut_mac_address})'

    port = net_perf_client.interfaces.net_perf.server_port
    logger().info(f"Port:{port}")
    packet_filter6 = f'udp.port eq {port}'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'

    # logger().info("Validating dhcp packets in sniffer")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
    #     'packet_count'], 'Unable to find dhcp packets'

    # logger().info("Validating udp packet")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
    #     'packet_count'], 'Unable to find udp packet'

    logger().info("Initiating BLE disconnection from DUT")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_addr, timeout=30)


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
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
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_ble_smp_pair_response_C20196(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client,
                                      ble_client, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_smp_pair_response_C20196"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)
    t1.start()
    time.sleep(15)

    ble_mode = "ble_slave"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_addr, ble_dut_addr = ble_master_slave(wifi_dut, ble_client, ble_mode, secure_connect=True)

    logger().info(f"Waiting for 60 seconds for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    t1.wait_for_exit(True)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    # Validate dhcp packets in sniffer
    packet_filter5 = f'(dhcp) && (wlan.addr == {ap_bssid}) && (wlan.addr == {dut_mac_address})'

    port = net_perf_client.interfaces.net_perf.server_port
    logger().info(f"Port:{port}")
    packet_filter6 = f'tcp.port eq {port}'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'

    # logger().info("Validating dhcp packets in sniffer")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
    #     'packet_count'], 'Unable to find dhcp packets'

    # logger().info("Validating tcp packet")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
    #     'packet_count'], 'Unable to find tcp packet'

    logger().info("Initiating BLE disconnection from remote device")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_addr)


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_ble_smp_passkey_C20197(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client, ble_client,
                                protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_smp_passkey_C20197"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    ble_mode = "ble_master"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_addr, _ = ble_master_slave(wifi_dut, ble_client, ble_mode)

    logger().info("Checking connection status after 60 seconds")
    time.sleep(60)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    t1.wait_for_exit(True)
    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    # Validate dhcp packets in sniffer
    packet_filter5 = f'(dhcp) && (wlan.addr == {ap_bssid}) && (wlan.addr == {dut_mac_address})'

    port = net_perf_client.interfaces.net_perf.server_port
    logger().info(f"Port:{port}")
    packet_filter6 = f'udp.port eq {port}'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'

    # logger().info("Validating dhcp packets in sniffer")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
    #     'packet_count'], 'Unable to find dhcp packets'

    # logger().info("Validating udp packet")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
    #     'packet_count'], 'Unable to find udp packet'

    logger().info("Initiating BLE disconnection from DUT")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_addr, timeout=30)


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_multi_gatt_conn")
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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_get_attribute_descriptors_value_C20190(firmware_loader, wifi_dut, wifi_sniffer, wifi_access_point,
                                                net_perf_client, wifi_client,
                                                ble_client, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_get_attribute_descriptors_value_C20190"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    logger().info("start ble GATT service in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert ble_dut_address, "Unable to find ble_dut_address"

    ble_client.interfaces.bluetooth.close()
    time.sleep(2)
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address,
                                                                       service_classes=[HeartRateService])

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    logger().info("Start scanning and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=80)
    wifi_dut.interfaces.wifi.ble_stop_scanning()

    logger().info(f"Initiating connection this can take some time...")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")

    # get all profiles
    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address, timeout=30)
    logger().info(f"UUID's are:{uuids}")
    assert HeartRateService.UUID.lower() in uuids

    # resolve HeartRate profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=ble_client_address,
                                                                              uuid=int(HeartRateService.UUID, 16))
    assert start_handle is not None
    assert end_handle is not None

    # resolve characteristics of HeartRate profile
    uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address, start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    logger().info(f"UUID's are:{uuids}\nwrite_handles:{write_handles}")

    assert BodySensorLocationCharacteristic.Sensor_Location_UUID in uuids, "Unable to find BodySensor uuid"
    index = uuids.index(BodySensorLocationCharacteristic.Sensor_Location_UUID)

    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert BodySensorLocationCharacteristic.prop_int == int(char_properties[index]), "Invalid character property found"

    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "Unable to get write handle for configured service"

    # read value
    logger().info("Getting attribute value for configured service")
    att_value = wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_remote_dev_address=ble_client_address,
                                                                 char_property=write_handle)
    assert int(att_value) > 0, "Attribute value not found"
    logger().info(f"Attribute Value is:{att_value}")
    t1.wait_for_exit(True)

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    # Validate dhcp packets in sniffer
    packet_filter5 = f'(dhcp) && (wlan.addr == {ap_bssid}) && (wlan.addr == {dut_mac_address})'

    port = net_perf_client.interfaces.net_perf.server_port
    logger().info(f"Port:{port}")
    packet_filter6 = f'udp.port eq {port}'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'

    # logger().info("Validating dhcp packets in sniffer")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5)[
    #     'packet_count'], 'Unable to find dhcp packets'

    # logger().info("Validating tcp packet")
    # assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter6)[
    #     'packet_count'], 'Unable to find tcp packet'

    logger().info("Initiating BLE disconnection from DUT")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)


# @pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_disconnect"])
def test_sta_ble_verify_msg_power_save_C20275(wifi_dut, wifi_sniffer, wifi_access_point, wifi_client, ble_client,
                                              utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    ping_count_bytes = utf_constants.get("ping_count")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_C20275"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    ble_mode = "ble_slave"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_addr, ble_dut_addr = ble_master_slave(wifi_dut, ble_client, ble_mode, secure_connect=True)

    # DO PING
    logger().info(f"Initiating wlan ping with {ping_count_bytes} bytes")
    status = ping(device_ip, ping_count_bytes)
    assert status == 1, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()
    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'

    logger().info("Initiating BLE disconnection from DUT")
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_addr)


# ################################# PR2 #############################################
#pytest.mark.skip()
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.parametrize("test_run_time", [300])
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
def test_wlan_and_ble_radio_on_off_C20202(wifi_dut, ble_client, wifi_access_point, test_run_time):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    sw = Stopwatch()
    while sw.elapsed_sec < test_run_time:
        logger().info(f"Time left to complete this testcase is '{round((test_run_time / 60), 2)}' minutes")
        logger().info("Disabling wlan radio of the DUT")skip
        wifi_dut.interfaces.wifi.wlan_request_radio(0)
        logger().info("Disabled wlan radio of the DUT")
        time.sleep(2)
        logger().info("Enabling wlan radio of the DUT")
        wifi_dut.interfaces.wifi.wlan_request_radio(1)
        logger().info("Enabled wlan radio of the DUT")
        time.sleep(1)
        logger().info("Disabling bt radio of the DUT")
        wifi_dut.interfaces.wifi.bt_deinit()
        logger().info("Disabled bt radio of the DUT")
        time.sleep(2)
        logger().info("Enabling bt radio of the DUT")
        wifi_dut.interfaces.wifi.bt_init()
        logger().info("Enabled bt radio of the DUT")
