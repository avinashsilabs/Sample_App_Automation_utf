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
from threading import Thread

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


class FilterPacket:
    def get_association_id(self):
        # This function will parse the pacap file and find & return the association id
        packet_filter = "= Association ID:"
        association_id = None
        count = 0

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for x in line:
            count = count + 1
            if packet_filter in x:
                association_id = x.strip().split(':')[1].strip()
                print(f'Association id = {association_id}')
                break
        filter_file.close()
        return association_id

    def parse_sniffer_packets(self):
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        sniffer_dict = dict()

        """This function takes the filter2_file.txt as a input and parse all captured sniffer packet and convert into
        dictionary as per given input"""
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()

            if packet_type in line:
                if packet_filter_beacon.strip() == line.strip():
                    sniffer_dict[frame_num] = 'beacon'
                if packet_filter_ps_poll.strip() == line.strip():
                    sniffer_dict[frame_num] = 'PS-Poll'
                if packet_filter_data.strip() == line.strip():
                    sniffer_dict[frame_num] = 'Data'
        return sniffer_dict

    def match_packet_sequence(self, sniffer_dict):
        ps_status = False
        data_status = False
        beacon_key = 0
        ps_key = 0
        data_key = 0
        count = 0
        """This function validates the packet sequence for DTIM count reaches 0(As per test case requirement need to validate 
        Beacon-> Ps-Poll-> Data packets sequentially"""

        for key, value in sniffer_dict.items():
            if value == 'beacon':
                beacon_key = key
            if value == 'PS-Poll':
                if int(key) == int(beacon_key) + 1:
                    ps_key = key
                    ps_status = True
                else:
                    ps_status = False
            if value == 'Data':
                if int(key) == int(ps_key) + 1:
                    data_key = key
                    data_status = True
                else:
                    data_status = False
            if ps_status and data_status:
                logger().info(f'Sequence of TIM Beacon frame = {beacon_key}, PS-Poll = {ps_key}, Data = {data_key}\n')
                ps_status = False
                data_status = False
                count = count + 1

        return False if count == 0 else True

    def parse_sniffer_packet_more_data(self):
        packet_type = "    Type/Subtype:"
        packet_filter_frame = '    Frame Number:'
        packet_filter_beacon = '    Type/Subtype: Beacon frame (0x0008)'
        packet_filter_data = '    Type/Subtype: QoS Data (0x0028)'
        packet_filter_ps_poll = '    Type/Subtype: Power-Save poll (0x001a)'
        packet_filter_more_data_enable = '            ..1. .... = More Data: Data is buffered for STA at AP'
        packet_filter_more_data_disable = '            ..0. .... = More Data: No data buffered'

        sniffer_dict = dict()
        frame_num = 0
        filter_file = open(f'./reports/filter2_file.txt', 'r')
        file_line_list = filter_file.readlines()

        for line in file_line_list:
            if packet_filter_frame in line:
                frame_num = line.split(':')[1].strip()
            if packet_type in line:
                if packet_filter_ps_poll.strip() == line.strip():
                    sniffer_dict[frame_num] = 'PS-Poll'
            if packet_filter_more_data_enable in line:
                sniffer_dict[frame_num] = 'More Data'
            if packet_filter_more_data_disable in line:
                sniffer_dict[frame_num + 'N'] = 'No Data'
            if packet_filter_beacon in line:
                sniffer_dict[frame_num] = 'beacon'
        filter_file.close()
        return sniffer_dict

    def validate_data_packet_with_more_bit_enable(self, sniffer_dict):
        ps_status = False
        no_more_data_status = False
        beacon_status = False
        ps_key = 0
        more_key = 0
        beacon_key = 0
        no_more_data_key = 0
        status_more_data = 0
        status_beacon = 0
        more_key_status = False
        status = True

        for key, value in sniffer_dict.items():
            if value == 'More Data' or ((value == 'More Data') and (int(key) == int(ps_key) + 1)):
                more_key = key
                more_key_status = True
            if value == 'PS-Poll':
                if (int(key) == int(more_key) + 1) and (more_key_status is True):
                    ps_key = key
                    ps_status = True
            if (value == 'No Data') and (key == str(ps_key) + 'N'):
                # this is More data filed 0 belongs to PS-Poll packet no wouldn't count
                pass
            if (value == 'No Data') and (key != str(ps_key) + 'N'):
                # this is Qos data packet with More data filed 0 and we are expecting next packet should be beacon
                no_more_data_key = key
                no_more_data_status = True
            if (value == 'beacon') and (no_more_data_status is True):
                # Verifying whether beacon packet is next to QoS Data with More bit 0
                if int(key) == int(no_more_data_key.split('N')[0]) + 1:
                    beacon_key = key
                    beacon_status = True

            if more_key_status is True and ps_status is True:
                # if Qos Data with More data bit 1 and Ps-Poll packet comes consecutively then pass the test case
                logger().info(f'Qos Data with More data 1 = {more_key}, PS-Poll = {ps_key}')
                ps_status = False
                more_key_status = False
                status_more_data = status_more_data + 1

            if beacon_status:
                # if Qos Data with More data bit 0 and Beacon packet comes consecutively then pass the test case
                logger().info(f'Qos Data with More data 0 = {no_more_data_key}, Beacon = {beacon_key}')
                beacon_status = False
                no_more_data_status = False
                status_beacon = status_beacon + 1

        if status_beacon == 0:
            logger().info(f'Expecting Beacon after Data packet with More bit value 0(QoS + More data bit 0 -> Beacon')
            status = False
        if status_more_data == 0:
            logger().info(f'Expecting PS-Poll after Data packet with More bit enable(QoS + More data bit 1 -> Ps-Poll)')
            status = False
        return status


def wifi_join(wifi_dut, wifi_access_point):
    wifi_dut.interfaces.wifi.associated = False
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
            logger().info(f'DUT ip {device_ip}')
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
            time.sleep(15)
    assert ip_fail == 0, "ip setting in DUT has failed"

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
            time.sleep(10)
    return device_ip


def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True, skip_scan=False,
                     secure_connect=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT", ):
    ble_dut_address = ble_dut_address
    ble_client_address = None
    if mode == "ble_master":
        try:
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
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning ***************")
            ble_client.interfaces.bluetooth.stop_advertising()
            wifi_dut.interfaces.wifi.ble_stop_scanning()
            raise e
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected, timeout=120)
        time.sleep(2)
        logger().info("BLE Master Connection Success")

    if mode == "ble_slave":
        try:
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
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning ***************")
            wifi_dut.interfaces.bluetooth.ble_stop_advertising()
            ble_client.interfaces.wifi.stop_scanning()
            raise e
        if secure_connect:
            ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=ble_dut_address)
        else:
            ble_client.interfaces.bluetooth.connect(ble_dut_address)
            time.sleep(2)
            logger().info("BLE Slave Connection Success")
    return ble_client_address, ble_dut_address


def run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
    logger().info(f"Initiating wlan data transfer with protocol {protocol} from DUT")
    logger().info("Getting Host IP address")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")
    # starting iperf
    logger().info("Configuring iperf server remotely")
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    time.sleep(2)
    logger().info("Starting server from remote device")
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


pytestmark = [pytest.mark.ble_client("raspi_ble_client"), pytest.mark.wifi_client("raspi_wifi"),
              pytest.mark.config("wifi_access_point", wifi={"channel": 8}),
              pytest.mark.config("wifi_client", wifi={"interface": "eth0"})]


@pytest.mark.skip("Needs test agent support for ble connection using LTK and IRK Keys, Jira:WIFI_BT_UTFHELP-1067")
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
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
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
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
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
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
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
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
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

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)
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
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_get_attribute_descriptors_value_C20190(firmware_loader, wifi_dut, wifi_sniffer, wifi_access_point,
                                                net_perf_client, wifi_client, ble_client, protocol, utf_constants):
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

    traffic_thread = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)
    try:
        logger().info("start ble GATT service in DUT")
        ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
        assert ble_dut_address, "Unable to find ble_dut_address"

        logger().info("Starting DUT BLE advertising")
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(3)

        logger().info("Initiating wlan data transfer from DUT")
        traffic_thread.start()

        logger().info(f"Configuring HeartRateService and Initiating BLE scan from remote device")
        ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                            service_classes=[HeartRateService])
        assert ble_client_address, f"Unable to get ble_client_address"
        time.sleep(2)
        ble_client.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        assert ble_dut_address in found_devices, "Unable to find DUT BLE from remote device scan list"
        logger().info(f"BLE Scan list: {found_devices}")
        logger().info(f"See that we found our device: '{ble_dut_address}'")

        logger().info("Connecting ble_client to DUT")
        conn_params = {"min_conn_interval": 40,
                       "max_conn_interval": 40,
                       "conn_latency": 0,
                       "supervision_timeout": 200}
        ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                min_conn_interval=conn_params["min_conn_interval"],
                                                max_conn_interval=conn_params["max_conn_interval"],
                                                conn_latency=conn_params["conn_latency"],
                                                supervision_timeout=conn_params["supervision_timeout"])
        time.sleep(10)
        logger().info("BLE SLAVE connection successful")
    except Exception as e:
        logger().info("*************** Exception block for stop advertising and stop scanning ***************")
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        ble_client.interfaces.bluetooth.stop_scanning()
        raise e

    # resolve HeartRate profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=ble_client_address,
                                                                              uuid=int(HeartRateService.UUID, 16),
                                                                              timeout=30)
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
    traffic_thread.wait_for_exit(True)

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

    logger().info("Initiating WLAN disconnection from DUT")
    wifi_dut.interfaces.wifi.leave()


# @pytest.mark.skip()
@pytest.mark.firmware_app("test_wlan_powersave_mode3_lp")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_sta_ble_verify_msg_power_save_C20275(firmware_loader, wifi_dut, wifi_sniffer, wifi_access_point, wifi_client,
                                              ble_client, utf_constants):
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


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20344', "security": "WPA2", "dtim": 3})
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
        "rejoin_max_retry": 0,
        "scan_interval": 4,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
    },
)
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_sta_ble_powersave_mode2_with_wlan_and_ble_connected_sleep_C20344(wifi_dut, wifi_sniffer,
                                                                          wifi_access_point, ble_client,
                                                                          net_perf_client, wifi_client,
                                                                          protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ble_client.interfaces.bluetooth.close()
    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    validation = True
    assoc_obj = FilterPacket()
    ps_packet_exchange_obj = FilterPacket()
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="Capture__C20344")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()
    time.sleep(5)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_addr, ble_dut_addr = ble_master_slave(wifi_dut, ble_client, ble_mode)
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
    # Assoc resp frame in sniffer
    packet_filter1 = f'((wlan.fc.type_subtype == 0x0001) && (wlan.sa == {ap_bssid} && (wlan.da == {dut_mac_address})))'
    packet_filter2 = "    Type/Subtype: Association Response (0x0001)"
    packet_filter3 = '    Type/Subtype: Power-Save poll (0x001a)'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
        'packet_count'], "Unable to find probe request packet"

    time.sleep(5)
    association_id = assoc_obj.get_association_id()
    if association_id is None:
        logger().info(f'Unable to find ASSOCIATION-ID={association_id}')
        assert False, f"Unable to find ASSOCIATION-ID={association_id}"
    else:
        logger().info(f'\n\n *** ASSOCIATION-ID={association_id} *** \n')

    # Applying filter to find the Beacon with (association-id + DTIM count 0) -> Ps-Poll with PM bit = 1 -> Qos data
    packet_filter4 = f'(wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0x001a) || ' \
                     f'(wlan.addr == {ap_bssid} && ' \
                     f'(wlan.fc.type_subtype ==8) || (wlan.fc.type_subtype==0x0028) || (wlan.fc.type_subtype==0x002c))'

    # Applying filter to find the beacon with association-id and PS-poll packet with pm bit enable -> Qos
    packet_filter5 = f'(wlan.fc.type_subtype == 0x001a || wlan.fc.type_subtype == 0x0028) || (wlan.tim.dtim_count == 0 ' \
                     f'&& wlan.tim.dtim_period == 3 && wlan.tim.aid == {association_id})'

    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], "Unable to find PS poll packet"

    # Validate beacon DTIM count=0
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter5, packet_filter4)[
        'packet_count']

    logger().info('-----------Validation for DTIM count = 0 sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packets()
    assert ps_packet_exchange_obj.match_packet_sequence(sniffer_dict), 'No sequence found for sniffer packets ' \
                                                                       'Beacon(DTIM count=0)-> Ps-Poll-> Data'

    logger().info('-----------Validation for More data bit sequence---------------- ')
    sniffer_dict = ps_packet_exchange_obj.parse_sniffer_packet_more_data()
    assert ps_packet_exchange_obj.validate_data_packet_with_more_bit_enable(sniffer_dict), \
        'No sequence found for sniffer packets Qos data with More bit set -> Ps-Poll -> Qos data/Beacon'

    logger().info("Initiating BLE disconnection from remote device")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_addr)


# ################################# PR2 #############################################
# pytest.mark.skip()
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
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_wlan_and_ble_radio_on_off_C20202(wifi_dut, ble_client, wifi_access_point, test_run_time):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    sw = Stopwatch()
    while sw.elapsed_sec < test_run_time:
        logger().info(
            f"Remaining time to complete this testcase is '{round(((test_run_time - sw.elapsed_sec) / 60), 2)}' minutes")
        logger().info("Disabling wlan radio of the DUT")
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
        logger().info("\n\n")


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "ble_stop_adv", "ble_stop_scan"])
def test_verify_ble_advertise_and_scan_functionality_dut_in_connected_state_c20198(wifi_dut, ble_clients,
                                                                                   wifi_access_point, wifi_sniffer):
    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"

    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    ble_client1.interfaces.bluetooth.close()
    ble_client2.interfaces.bluetooth.close()
    channel = wifi_access_point.interfaces.wifi.channel
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="Capture_c20198")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_fail = 1
    device_ip = None
    for count in range(3):
        try:
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            ip_fail = 0
            logger().info(f'DUT ip {device_ip}')
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
            time.sleep(10)
    assert ip_fail == 0, "ip setting in DUT has failed"

    logger().info("Started BLE in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, f"ble_start failed , Unable to fetch ble dut address"

    try:
        ble_client1.interfaces.bluetooth.close()
        logger().info("Start DUT advertising")
        wifi_dut.interfaces.wifi.ble_start_advertising()
        time.sleep(2)
        ble_client2_address = ble_client2.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
        assert ble_client2_address, f"failed to initiate ble in remote device, Unable to fetch ble_client_address"
        time.sleep(5)
        logger().info(f"Start scanning {ble_client2.name}")
        wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client2_address, timeout=80)

        logger().info(f"Initiating scan from {ble_client1.name}")
        # Begin Scanning for BLE devices
        bt_client_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert bt_client_address is not None, "Unable to fetch MAC address from Remote device"

    except Exception as e:
        logger().info("*************** Exception block for stop advertising and stop scanning ***************")
        ble_client2.interfaces.bluetooth.stop_advertising()
        wifi_dut.interfaces.wifi.ble_stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        raise e

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
            logger().info("pinging to dut after powersave.....")
            status = ping(device_ip, ping_count)
            assert status, "DUT not responding for ping request......"
            logger().info("ping to DUT is successful....")
            logger().info(f'DUT ip {device_ip}')
            break
        except:
            logger().info(f"DUT not responding for ping request..retry count -> {count + 1}")
            time.sleep(10)

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    wifi_dut.interfaces.wifi.ble_stop_scanning()

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    # Validate qos data packets should be observed with more data bit set to 1
    packet_filter3 = f'(wlan.ta == {ap_bssid}) && (wlan.da=={dut_mac_address}) && (wlan.fc.moredata==1)'

    # Validate PS Polls with power management Bit set to 1
    packet_filter4 = f'(wlan.addr == {dut_mac_address} || wlan.fc.type_subtype == 0x001a)'

    logger().info("Validating qos data packets should be observed with more data bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)[
        'packet_count'], 'Unable to find qos data packets should be observed with more data bit set to 1'

    logger().info("Validating PS Polls with power management Bit set to 1")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter4)[
        'packet_count'], 'Unable to find PS Polls with power management Bit set to 1'


@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "ble_stop_adv", "ble_stop_scan"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_validate_ble_services_when_dut_in_connected_state_c20200(firmware_loader, wifi_dut, ble_client,
                                                                  wifi_access_point, wifi_sniffer):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    service_uid = "00001803-0000-1000-8000-00805f9b34fb"
    char_uid = "00002a06-0000-1000-8000-00805f9b34fb"

    # BLE DUT initialization
    logger().info(" ******* Start BLE GATT service ******* ")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address, "Failed to load bt address..."

    # adding services, attributes and values
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x1803)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)

    # Advertise data from DUT
    logger().info("start ble advertising....")
    wifi_dut.interfaces.wifi.ble_start_advertising()

    logger().info("scanning for ble client.. ")
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address, "The client address is not found"
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()

    logger().info("verifying device in scan list...")
    found_devices = ble_client.interfaces.bluetooth.get_devices()

    assert wifi_dut.interfaces.wifi.ble_address in found_devices, "failed to find dut address in scan list..."
    assert (found_devices[
                wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "failed to find dut in scan list..."

    logger().info("connecting to dut....")
    ble_client.interfaces.bluetooth.connect(bt_dut_address)
    # stability for 60sec and then disconnection
    time.sleep(60)

    logger().info("verifying dut state after the conn......")
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"

    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)
    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"
    ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path)

    channel = wifi_access_point.interfaces.wifi.channel
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    wifi_join(wifi_dut, wifi_access_point)

    logger().info("Disconnecting from dut...")
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
