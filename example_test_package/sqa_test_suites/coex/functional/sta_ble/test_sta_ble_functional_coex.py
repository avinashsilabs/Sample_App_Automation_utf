import re
import time
from random import randint
from retry import retry
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
    RS9116PowerSaveProcedureTypes, DeviceConstants, RS9116BLEFeatureBitMap, RS9116BLECustomFeatureBitMap, RS9116MqttQos, \
    RS9116JoinFeatureBitMap, RS9116CertificateType
from utf.utils.iperf.iperf_utils import print_dict
from utf.interfaces.iperf.iperf_constants import IperfConstants
from utf.interfaces.bluetooth import BLEDeviceState
from utf.utils.iperf.iperf_utils import ping
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import HeartRateService
from utf.interfaces.bluetooth.bluez.gatt_application.heart_rate_service import BodySensorLocationCharacteristic
from utf.interfaces.bluetooth.bluez.gatt_application.immediate_alert_service import ImmediateAlertService, \
    ImmediateAlertLevelCharacteristic
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.bluetooth.bluez.gatt_application.link_loss_service import LinkLossService, \
    LinkLossAlertLevelCharacteristic
from utf.utils import get_tls_certificate_dir

"""
    Setup Requirement: DUT(RS9116) , EFR32, 2 Raspberry PI required [ 2 BLE CLIENTS],
    Access Point(Third Party AP'), Sniffer(NUC) , 
    Reported by cg team:  rashmi & team
    Description:Sta_ble_coex_basic_functionality Test cases
"""

iperf_started = False
ping_count = 30


def logger():
    return get_logger(__name__)


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


def wifi_join(wifi_dut, wifi_access_point, powersave=True):
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

    if powersave:
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
                     secure_connect=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT"):
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
            conn_params = {"min_conn_interval": 40,
                           "max_conn_interval": 40,
                           "conn_latency": 0,
                           "supervision_timeout": 200}
            ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                                    min_conn_interval=conn_params["min_conn_interval"],
                                                    max_conn_interval=conn_params["max_conn_interval"],
                                                    conn_latency=conn_params["conn_latency"],
                                                    supervision_timeout=conn_params["supervision_timeout"])
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


def wlan_scan(wifi_dut, channel=None):
    for count in range(5):
        try:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
            assert len(scan_results) > 0, "scan_list not found"
            logger().info(scan_results)
            break
        except Exception as e:
            logger().info(f"Scanning to the Wifi Access point is failed. retry count -> {count}")
            time.sleep(1)
            if "0x21" in str(e):
                logger().info(f"Device already in connected state, need to disconnect before scan")
                wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                time.sleep(5)
                if count == 4:
                    raise


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
              pytest.mark.config("wifi_access_point", wifi={"channel": 8})]


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
def test_ble_encryption_C133440(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client, ble_client,
                                protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_encryption_C133440"
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
def test_ble_smp_pair_request_C133441(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client,
                                      ble_client, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_smp_pair_request_C133441"
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
def test_ble_smp_pair_response_C133442(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client,
                                       ble_client, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_smp_pair_response_C133442"
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
def test_ble_smp_passkey_C133443(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client, wifi_client, ble_client,
                                 protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_smp_passkey_C133443"
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
def test_get_attribute_descriptors_value_C133436(firmware_loader, wifi_dut, wifi_sniffer, wifi_access_point,
                                                 net_perf_client, wifi_client, ble_client, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_get_attribute_descriptors_value_C133436"
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
@pytest.mark.test_wlan_powersave_mode3_lp
def test_sta_ble_verify_msg_power_save_C133515(firmware_loader, wifi_dut, wifi_sniffer, wifi_access_point, wifi_client,
                                               ble_client, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    time_duration = utf_constants.get("time_duration")
    ping_count_bytes = utf_constants.get("ping_count")
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_C133515"
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
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C133513', "security": "WPA2", "dtim": 3})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Default,
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
def test_sta_ble_powersave_mode2_with_wlan_and_ble_connected_sleep_C133513(wifi_dut, wifi_sniffer,
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
    wifi_sniffer.interfaces.capture.start_capture(capture_file="Capture__C133513")
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
def test_wlan_and_ble_radio_on_off_C133448(wifi_dut, ble_client, wifi_access_point, test_run_time):
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
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "ble_stop_adv", "ble_stop_scan"])
def test_verify_ble_advertise_and_scan_functionality_dut_in_connected_state_C133444(wifi_dut, ble_clients,
                                                                                    wifi_access_point, wifi_sniffer):
    assert len(ble_clients) >= 2, f"Minimum 2 raspi devices needed for this test"

    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    ble_client1.interfaces.bluetooth.close()
    ble_client2.interfaces.bluetooth.close()
    channel = wifi_access_point.interfaces.wifi.channel
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="Capture_C133444")
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
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
        logger().info(f"Initiating scan from {wifi_dut.name} \n ble_client2_address:{ble_client2_address}")
        dut_scan_result = wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client2_address,
                                                                      timeout=80)
        logger().info(f" scan result '{dut_scan_result}")

        logger().info(f"Initiating scan from {ble_client1.name}\nble_dut_address:{ble_dut_address}")
        # Begin Scanning for BLE devices
        bt_client1_address = ble_client1.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert bt_client1_address is not None, "Unable to fetch MAC address from Remote device"

        device_found = False
        sw = Stopwatch()
        while sw.elapsed_sec < 30:
            if ble_dut_address in ble_client1.interfaces.bluetooth.get_devices():
                device_found = True
                break
        logger().info("stop scanning.....")
        ble_client1.interfaces.bluetooth.stop_scanning()
        assert device_found, "Unable to scan device"
        logger().info(f"ble_dut_address- {ble_dut_address} found in {ble_client1.name} scan list")

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
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "bt_features": RS9116BTFeatureBitMap.BLEFeatureBitmapValid | RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 |
                           RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "ble_stop_adv", "ble_stop_scan"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_validate_ble_services_when_dut_in_connected_state_C133446(firmware_loader, wifi_dut, ble_client,
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
    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=0)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi on DUT")
    wifi_join(wifi_dut, wifi_access_point)

    logger().info("Disconnecting from dut...")
    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.parametrize("protocol", [IperfConstants.TCP])
@pytest.mark.firmware_app("test_multi_gatt_conn")
@pytest.mark.config("wifi_dut",
                    wifi={
                        "oper_mode": 0,
                        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
                        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.FEAT_DEV_TO_HOST_ULP_GPIO_1,
                        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
                        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default,
                        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
                        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
                        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
                        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
                        "set_send_feature_frame": True,
                    })
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                                         "ble_stop_adv", "ble_stop_scan", "ble_disconnect"])
def test_ble_pxp_link_loss_alert_functionality_dut_slave_tcp_tx_C133439(firmware_loader, wifi_dut, wifi_sniffer,
                                                                        wifi_access_point, net_perf_client, wifi_client,
                                                                        ble_client, protocol):
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_pxp_link_loss_alert_functionality_dut_slave_tcp_tx_C133439"
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
    device_ip = wifi_join(wifi_dut, wifi_access_point, powersave=False)

    ble_client.interfaces.bluetooth.close()
    # BLE DUT initialization
    logger().info(" ******* Start BLE GATT service ******* ")
    bt_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert bt_dut_address, "Failed to load bt address..."

    # adding services, attributes and values
    wifi_dut.interfaces.wifi.ble_add_service(uid=0x1803)
    wifi_dut.interfaces.wifi.ble_add_char_serv_att(uid=0x2A06)
    wifi_dut.interfaces.wifi.ble_add_char_val_att(uid=0x2A06)

    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(3)

    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()

    # Begin Scanning for BLE devices
    bt_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=bt_dut_address)
    assert bt_client_address is not None, "failed to start ble client"
    device_found = False
    sw = Stopwatch()
    while sw.elapsed_sec < 30:
        found_devices = ble_client.interfaces.bluetooth.get_devices()
        if bt_dut_address in found_devices and \
                found_devices[bt_dut_address] == wifi_dut.interfaces.wifi.ble_advertising_data:
            device_found = True
            break
    time.sleep(5)
    ble_client.interfaces.bluetooth.stop_scanning()
    assert device_found, "device isn't present in scan list..."
    conn_params = {"min_conn_interval": 40,
                   "max_conn_interval": 40,
                   "conn_latency": 0,
                   "supervision_timeout": 200}

    ble_client.interfaces.bluetooth.connect(dev_addr=bt_dut_address,
                                            min_conn_interval=conn_params["min_conn_interval"],
                                            max_conn_interval=conn_params["max_conn_interval"],
                                            conn_latency=conn_params["conn_latency"],
                                            supervision_timeout=conn_params["supervision_timeout"])
    time.sleep(10)

    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    # Get the state of the dut
    state = wifi_dut.interfaces.wifi.ble_get_device_state()
    state_int = int(state) if state.isdigit() else -1
    assert state_int == BLEDeviceState.Connected, "Device isn't in connected state"
    logger().info("DUT is in connection with remote BLE device ")

    servs, chars = ble_client.interfaces.bluetooth.gatt_adapter.resolve_all_services_characteristics()
    assert len(servs) > 0, "no services fetched"
    assert len(chars) > 0, "fetched characters are empty"

    service_uid = "00001803-0000-1000-8000-00805f9b34fb"
    char_uid = "00002a06-0000-1000-8000-00805f9b34fb"
    char_path, char_props = ble_client.interfaces.bluetooth.gatt_adapter.resolve_characteristic(services=servs,
                                                                                                service_uid=service_uid,
                                                                                                char_uid=char_uid)
    logger().info(f"char_path is {char_path}")
    assert char_path, "characters are empty"
    assert len(char_props) > 0, "length of characters is 0"

    for data in range(3):
        logger().info(f"The data being sent is {data}")
        ble_client.interfaces.bluetooth.gatt_adapter.write_charac_value(char_path=char_path, data=data)
        time.sleep(3)
        received = ble_client.interfaces.bluetooth.gatt_adapter.read_charac_value(char_path=char_path, type=int)
        assert received == data, "sent and received data isn't matching"

    ble_client.interfaces.bluetooth.disconnect(bt_dut_address)
    time.sleep(1)
    t1.wait_for_exit(True)

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ' \
                     f'ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == ' \
                     f'{ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

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


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.TCP_IP_TOTAL_SOCKETS_1,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.ConfigHttpOTAF | RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.EXT_DYNAMIC_COEX_MEMORY,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "set_send_feature_frame": True,
    },
)
@pytest.mark.http_server('raspi_lighttpd')
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "load_default_fw"])
def test_otaf_firmware_upgrade_through_wifi_after_ble_connection_C133484(wifi_dut, ble_client, wifi_access_point,
                                                                         wifi_sniffer, http_server):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ble_mode = "ble_slave"
    logger().info(f"Initiating DUT as Master connection with {ble_client.name} as slave")
    ble_client_address, ble_dut_address = ble_master_slave(wifi_dut, ble_client, ble_mode)
    logger().info(f"DUT as BLE_MASTER CONNECTION SUCCESSFUL with {ble_client.name}")

    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='Capture_test_C133484')
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    wifi_join(wifi_dut, wifi_access_point, powersave=False)
    time.sleep(2)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Checking connection status of BLE from DUT")
    check_connection_status(wifi_dut, ble=True)

    logger().info("checking http server stats....")
    server_stat = http_server.interfaces.http.started
    assert server_stat, "http server is inactive"
    logger().info(f'http server state is {server_stat}')

    logger().info("fetching http server ip....")
    host_ip = http_server.interfaces.http.hostname_or_ip_address
    logger().info(f"http server ip is {host_ip}")

    logger().info("pinging to http server ip....")
    status = ping(host_ip, 10)
    assert status, "unable to ping to http server"

    logger().info("dut fw version before upgrade...")
    fw_before_upgrade = wifi_dut.interfaces.wifi.version()

    logger().info("performing firmware upgrade....")
    wifi_dut.interfaces.wifi.upgrade_firmware_http(0, host_ip, 80)

    sw = Stopwatch()
    http_otaf_event = False
    while sw.elapsed_sec < 150:
        events = wifi_dut.interfaces.wifi.get_async_events()
        if len(events):
            for event in events:
                if event.event_type == RS9116AsyncEventType.HTTP_OTAF_STATUS:
                    http_otaf_event = True
                    break
        if http_otaf_event:
            logger().info(f"Time taken for otaf firmware upgrade is '{round(sw.elapsed_sec)}' seconds")
            break
    assert http_otaf_event, "http otaf async event not received from DUT"

    logger().info("\nInitiating Wireless Deinit on DUT")
    wifi_dut.interfaces.wifi.wireless_deinit(timeout=60)
    time.sleep(10)

    logger().info("Initialising DUT after the reset....")
    wifi_dut.interfaces.wifi.inited = False
    wifi_dut.interfaces.wifi.init(reset_type="rs911x")

    logger().info("\n\ndut fw version after upgrade...")
    fw_after_upgrade = wifi_dut.interfaces.wifi.version()
    time.sleep(2)
    logger().info(f"\nfirmware versions before otaf:{fw_before_upgrade}"
                  f"\nfirmware version after loading through otaf :{fw_after_upgrade}")
    assert fw_before_upgrade != fw_after_upgrade, "firmware versions should not match after loading firmware through otaf"

    logger().info("Stop Sniffer finally")
    wifi_sniffer.interfaces.capture.stop_capture()

    # Validate probe request from DUT
    packet_filter1 = f'(wlan.fc.type_subtype == 0x0004) && (wlan.sa == {dut_mac_address} && wlan.da == ff:ff:ff:ff:ff:ff)'

    # Validate association request and association response packets
    packet_filter2 = f'((wlan.addr == {dut_mac_address} && wlan.fc.type_subtype == 0) || eapol) and ((wlan.addr == {ap_bssid} && wlan.fc.type_subtype == 1) || eapol)'

    logger().info("Validating probe request packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
        'packet_count'], 'Unable to find probe request packets'

    logger().info("Validating association request and association response packets")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)[
        'packet_count'], 'Unable to find association request and association response packets'

    logger().info(f"Disconnect BLE from Remote device which is Master")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)


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
def test_query_att_descriptors_of_remote_ble_device_while_wlan_tcp_tx_C133435(firmware_loader, wifi_dut, wifi_sniffer,
                                                                              wifi_client, ble_client, protocol,
                                                                              wifi_access_point, net_perf_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    ble_client.interfaces.bluetooth.close()
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_query_attribute_descriptors_C133435"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    logger().info("Initiating wlan scan from DUT")
    wlan_scan(wifi_dut, channel=0)

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    traffic_thread = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)

    logger().info("start ble GATT service in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert ble_dut_address, "Unable to find ble_dut_address"

    logger().info("Starting DUT BLE advertising")
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(5)

    logger().info("Initiating wlan data transfer from DUT")
    traffic_thread.start()

    logger().info(f"Configuring HeartRateService and Initiating BLE scan from remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                        service_classes=[HeartRateService])
    assert ble_client_address, f"Unable to get ble_client_address"
    time.sleep(1)
    ble_client.interfaces.bluetooth.stop_scanning()
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut_address in found_devices, "Unable to find DUT BLE from remote device scan list"
    logger().info(f"BLE Scan list: {found_devices}")
    logger().info(f"See that we found our device: '{ble_dut_address}'")

    logger().info("Connecting ble_client to DUT")
    ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address)
    time.sleep(10)
    logger().info("BLE SLAVE connection successful")

    # resolve HeartRate profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=ble_client_address,
                                                                              uuid=int(HeartRateService.UUID, 16),
                                                                              timeout=30)

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

    logger().info("Getting attribute descriptors of remote BLE device")
    wifi_dut.interfaces.wifi.ble_get_att_descriptor(ble_client_address, start_handle, end_handle)
    time.sleep(30)
    traffic_thread.wait_for_exit(True)

    logger().info(f"Waiting for '60' seconds for checking connection stability")
    time.sleep(60)
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
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)

    logger().info("Initiating WLAN disconnection from DUT")
    wifi_dut.interfaces.wifi.leave()


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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_set_att_value_with_diff_lengths_to_remote_ble_device_while_tcp_tx_C133437(firmware_loader, wifi_dut,
                                                                                   wifi_sniffer, protocol, wifi_client,
                                                                                   utf_constants, wifi_access_point,
                                                                                   net_perf_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    ble_client.interfaces.bluetooth.close()
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_set_att_value_C133437"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    logger().info("Initiating wlan scan from DUT")
    wlan_scan(wifi_dut, channel=0)

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    traffic_thread = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)
    logger().info("start ble GATT service in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert ble_dut_address, "Unable to find ble_dut_address"

    logger().info("Starting DUT BLE advertising")
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(5)

    logger().info("Initiating wlan data transfer from DUT")
    traffic_thread.start()

    logger().info(f"Configuring ImmediateAlertService and Initiating BLE scan from remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address,
                                                                        service_classes=[ImmediateAlertService])
    assert ble_client_address, f"Unable to get ble_client_address"
    time.sleep(2)
    ble_client.interfaces.bluetooth.stop_scanning()
    found_devices = ble_client.interfaces.bluetooth.get_devices()
    assert ble_dut_address in found_devices, "Unable to find DUT BLE from remote device scan list"
    logger().info(f"BLE Scan list: {found_devices}")
    logger().info(f"See that we found our device: '{ble_dut_address}'")
    conn_params = {"min_conn_interval": 40,
                   "max_conn_interval": 40,
                   "conn_latency": 0,
                   "supervision_timeout": 200}
    ble_client.interfaces.bluetooth.connect(dev_addr=ble_dut_address,
                                            min_conn_interval=conn_params["min_conn_interval"],
                                            max_conn_interval=conn_params["max_conn_interval"],
                                            conn_latency=conn_params["conn_latency"],
                                            supervision_timeout=conn_params["supervision_timeout"])
    time.sleep(15)
    logger().info("BLE SLAVE connection successful")

    # resolve ImmediateAlertService profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(ble_remote_dev_address=ble_client_address,
                                                                              uuid=int(ImmediateAlertService.UUID, 16),
                                                                              timeout=30)
    assert start_handle, "Unable to get start_handle of ImmediateAlertService"
    assert end_handle, "Unable to get end_handle of ImmediateAlertService"

    # resolve characteristics of ImmediateAlertService profile
    uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address, start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert ImmediateAlertLevelCharacteristic.LLA_UUID in uuids, "Unable to find ImmediateAlert uuid"
    index = uuids.index(ImmediateAlertLevelCharacteristic.LLA_UUID)
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert ImmediateAlertLevelCharacteristic.prop_int == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "Unable to get write handle for configured service"
    traffic_thread.wait_for_exit(True)

    alerts_allowed = {0: 'DEFAULT_ALERT', 1: 'MID_ALERT', 2: 'HIGH_ALERT'}
    logger().info(f"\n\nAlerts Allowed: {alerts_allowed}")
    for alert in alerts_allowed.keys():
        logger().info(f"\n\nSending alert data '{alert}' from DUT to remote BLE Device ")
        wifi_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=ble_client_address, char_property=write_handle,
                                                 value=alert)
        time.sleep(10)
        # read value
        received_alert = wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_client_address, write_handle)
        assert int(received_alert) == alert, "Sent alert and received alerts are not matching"
        logger().info(f"Received alert data:'{received_alert}'")

    logger().info(f"\n\nWaiting for '60' seconds for checking connection stability")
    time.sleep(60)
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
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)

    logger().info("Initiating WLAN disconnection from DUT")
    wifi_dut.interfaces.wifi.leave()


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
        "bt_features": RS9116BTFeatureBitMap.RFTypeSelection,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
@pytest.mark.firmware_app("test_multi_gatt_conn")
def test_ble_pxp_link_loss_alert_func_when_tcp_tx_is_in_progress_C133561(firmware_loader, wifi_dut,
                                                                         wifi_sniffer, protocol, wifi_client,
                                                                         utf_constants, wifi_access_point,
                                                                         net_perf_client, ble_client):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_pxp_link_loss_alert_C133561"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    logger().info("Initiating wlan scan from DUT")
    wlan_scan(wifi_dut, channel=0)

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point)

    traffic_thread = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=60)
    logger().info("start ble GATT service in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_gatt_start()
    assert ble_dut_address, "Unable to find ble_dut_address"

    logger().info("Initiating wlan data transfer from DUT")
    traffic_thread.start()

    ble_client.interfaces.bluetooth.close()
    logger().info(f"Configuring LinkLossService and Initiating BLE adv from remote device")
    ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address,
                                                                       service_classes=[LinkLossService])
    assert ble_client_address, f"failed to initiate ble in remote device, Unable to fetch ble_client_address"
    time.sleep(5)
    logger().info("Start scanning and connect to ble client")
    wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
    wifi_dut.interfaces.wifi.ble_stop_scanning()

    logger().info("Initiating BLE connection with ble_client")
    wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, timeout=120,
                                         expected="RSI_BLE_SECURITY_KEYS_EVENT")
    time.sleep(2)
    logger().info("DUT as BLE Master connection successful\n\n")

    uuids = wifi_dut.interfaces.wifi.ble_get_profiles_async(ble_remote_dev_address=ble_client_address)
    assert LinkLossService.UUID in uuids, "Unable fetch LinkLossService uuid from DUT"

    # resolve LinkLossService profile
    start_handle, end_handle = wifi_dut.interfaces.wifi.ble_get_profile_async(
        ble_remote_dev_address=ble_client_address,
        uuid=int(LinkLossService.UUID, 16),
        timeout=30)
    assert start_handle, "Unable to get start_handle of LinkLossService"
    assert end_handle, "Unable to get end_handle of LinkLossService"

    # resolve characteristics of LinkLossService profile
    uuids, write_handles, char_properties = wifi_dut.interfaces.wifi.ble_get_char_services_async(
        ble_remote_dev_address=ble_client_address, start_handle=int(start_handle, 16), end_handle=int(end_handle, 16))
    assert LinkLossAlertLevelCharacteristic.LLA_UUID in uuids, "Unable to find LinkLossService uuid"
    index = uuids.index(LinkLossAlertLevelCharacteristic.LLA_UUID)
    assert char_properties[index].isdigit(), "Character property found is not an integer"
    assert LinkLossAlertLevelCharacteristic.prop_int == int(char_properties[index]), "Invalid character property found"
    write_handle = int(write_handles[index], 16)
    assert write_handle > 0, "Unable to get write handle for configured service"
    traffic_thread.wait_for_exit(True)

    alerts_allowed = {0: 'NO_ALERT', 1: 'MID_ALERT', 2: 'HIGH_ALERT'}
    logger().info(f"\n\nAlerts Allowed: {alerts_allowed}")
    for alert in alerts_allowed.keys():
        logger().info(f"\n\nSetting alert level '{alert}' from DUT to remote BLE Device ")
        wifi_dut.interfaces.wifi.ble_set_att_cmd(ble_remote_dev_address=ble_client_address, char_property=write_handle,
                                                 value=alert)
        time.sleep(5)
        # read value
        received_alert = wifi_dut.interfaces.wifi.ble_get_att_value_async(ble_client_address, write_handle)
        assert int(received_alert) == alert, "Sent alert and received alerts are not matching"
        logger().info(f"Received alert level:'{received_alert}'")

    logger().info(f"\n\nWaiting for '60' seconds for checking connection stability")
    time.sleep(60)
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
    wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address, timeout=30)

    logger().info("Initiating WLAN disconnection from DUT")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.HTTPServer | RS9116TCPIPFeatureBitMap.HTTPClient | RS9116TCPIPFeatureBitMap.SSL | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid | RS9116TCPIPFeatureBitMap.DHCPv4Client,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_BI_DIR_ACK_UPDATE | RS9116ExtTCPIPFeatureBitMap.EnableMQTTFeature | RS9116ExtTCPIPFeatureBitMap.CONFIG_FEAT_EXTENTION_VALID,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "rejoin_max_retry": 10,
        "scan_interval": 6,
        "beacon_missed_count": 40,
        "first_time_retry": 0,
        "set_send_feature_frame": True,
    }
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut",
                       wifi=["mqtt_disconnect", "wifi_powersave_disable", "bt_powersave_disable", "disassociated",
                             "ble_stop_adv", "ble_stop_scan", "ble_disconnect"])
def test_mqtt_func_in_wlan_ble_mode_while_dut_ble_is_in_connection_with_remote_ble_dev_C133574(wifi_dut, wifi_sniffer,
                                                                                               mqtt_client, mqtt_server,
                                                                                               wifi_client, ble_client,
                                                                                               wifi_access_point):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_mqtt_func_in_wlan_ble_mode_C133574"
    validation = True
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    logger().info("Initiating wlan scan from DUT")
    wlan_scan(wifi_dut, channel=0)

    logger().info("Joining into Wi-Fi on DUT")
    wifi_join(wifi_dut, wifi_access_point, powersave=False)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Initiating BLE test with DUT as BLE Slave")
    mode = "ble_slave"
    _, ble_dut_address = ble_master_slave(wifi_dut, ble_client, mode)

    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    # Both DUT and third-party mqtt client connects to MQTT server
    topic = "mytesttopic"
    wifi_dut.interfaces["mqtt"] = wifi_dut.interfaces.wifi
    client_devices = [wifi_dut, mqtt_client]
    logger().info("Both DUT and third-party mqtt client connects to MQTT server")
    for device in client_devices:
        device.interfaces.mqtt.mqtt_client_connect_to_server(mqtt_server.interfaces.mqtt)
        time.sleep(5)
        if device.interfaces.mqtt.mqtt_client_is_connected:
            logger().info(f"MQTT Client:{device.name} subscribes to the topic with QOS 1")
            device.interfaces.mqtt.mqtt_client_subscribe(topic, qos=RS9116MqttQos.QOS1)

    # publish a message from the dut
    message1 = text_generator(20)
    logger().info(f"\n\nDUT is publishing message1:'{message1}' over the topic:'{topic}'")
    wifi_dut.interfaces.mqtt.mqtt_client_publish(topic, message1, qos=RS9116MqttQos.QOS1)

    logger().info("\nValidating received MQTT message1 from raspi_mqtt_client")
    sw = Stopwatch()
    msg = None
    while sw.elapsed_sec < 20:
        msg = mqtt_client.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msg):
            break
    assert len(msg) == 1, "Message1 is not received by mqtt-client"
    logger().info(
        f"QOS received: '{msg[0].qos}', mqtt topic received: '{msg[0].topic}', mqtt message received:'{msg[0].payload.decode()}'")
    assert msg[0].topic == topic, "Message1 not received by mqtt-client on subscribed topic"
    assert msg[0].payload.decode() == message1, "Published message1 is not matching with received message1"
    assert msg[0].qos == RS9116MqttQos.QOS1, "mqtt client received message1 with wrong QOS. expected is QOS1"
    time.sleep(3)
    logger().info("MQTT message1 validated successfully")

    # publish a message from the 3rd party mqtt_client
    message2 = text_generator(20)
    logger().info(f"\n\n3rd party mqtt client is publishing message2:'{message2}' over subscribed topic:'{topic}'")
    mqtt_client.interfaces.mqtt.mqtt_client_publish(topic, message2, qos=RS9116MqttQos.QOS1)

    logger().info("\nValidating received MQTT message2 from DUT")
    sw = Stopwatch()
    msg = None
    while sw.elapsed_sec < 20:
        msg = wifi_dut.interfaces.mqtt.mqtt_client_get_received_messages()
        if len(msg) == 2:
            break
    assert len(msg) == 2, "Message2 is not received by DUT"
    logger().info(
        f"QOS received: '{msg[1].qos}', mqtt topic received: '{msg[1].topic}', mqtt message received:'{msg[1].payload.decode()}'")
    assert msg[1].topic == topic, "Message2 not received by mqtt-client on subscribed topic"
    assert msg[1].payload.decode() == message2, "Published message2 is not matching with received message2"
    assert msg[1].qos == RS9116MqttQos.QOS1, "DUT received message2 with wrong QOS. expected is QOS1"
    logger().info("MQTT message2 validated successfully")

    logger().info(f"\n\nWaiting for '60' seconds for checking connection stability")
    time.sleep(60)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    logger().info("\nUnsubscribing from the topic....")
    wifi_dut.interfaces.mqtt.mqtt_client_unsubscribe(topic)

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

    logger().info("Initiating BLE disconnection from Raspi")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

    logger().info("Initiating WLAN disconnection from DUT")
    wifi_dut.interfaces.wifi.leave()


@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Default,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default | RS9116TCPIPFeatureBitMap.SSL,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Default | RS9116ExtCustomFeatureBitMap.UartSelForDebugPrints,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.Default | RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.EXT_TCP_IP_FEAT_SSL_MEMORY_CLOUD,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "bt_features": RS9116BTFeatureBitMap.Default,
        "ca_cert": ["ca-chain.cert.pem", "start_field.pem"],
        "client_cert": [False, "client-certificate.crt"],
        "client_key": [False, "private-key.key"],
    }
)
@pytest.mark.ble_client("raspi_ble_client")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.end_state("wifi_dut", wifi=["close_sockets", "wifi_powersave_disable", "disassociated"])
def test_func_and_data_transfer_of_2_ssl_socket_conn_while_ble_is_in_connection_C133575(wifi_dut, wifi_sniffer,
                                                                                        ble_client, wifi_access_point,
                                                                                        ssl_server):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    validation = True
    channel = wifi_access_point.interfaces.wifi.channel
    capture_filename = "test_ble_with_2_ssl_socket_133575"
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=f"{capture_filename}.pcap")
    time.sleep(3)

    logger().info("Initiating wlan scan from DUT")
    wlan_scan(wifi_dut, channel=0)

    logger().info("Joining into Wi-Fi on DUT")
    device_ip = wifi_join(wifi_dut, wifi_access_point, powersave=False)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    logger().info("Initiating BLE test with DUT as BLE Slave")
    mode = "ble_slave"
    _, ble_dut_address = ble_master_slave(wifi_dut, ble_client, mode)

    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "failed to enable bt power save"

    port1 = ssl_server.interfaces.ssl.config['device_port1']
    ssl_server.interfaces.ssl.start_server(port=port1)

    for sock_count in range(2):
        logger().info(f"Opening tcp client socket:{sock_count} over SSL from DUT")
        sock = wifi_dut.interfaces.wifi.open_tcp_client_socket(protocol=SocketOptions.SSL_ENABLE)
        assert sock == sock_count, f"socket id received is wrong, expected is {sock_count}"

        logger().info(f"Enabling SSL option for the socket-id->{sock} using rsi_set sockopt API")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_SSL_ENABLE,
                                                   SocketOptions.SSL_ENABLE)
        logger().info(f"Setting the tcp retry count for the socket_id->{sock} to {SocketOptions.TCP_MAX_RETRY} seconds")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        if sock_count == 0:
            socket_port = port1
            local_port = randint(5001, 20000)
            cert_index = SocketOptions.CERT_INDEX0
        else:
            socket_port = 8883
            local_port = randint(40001, 60000)
            cert_index = SocketOptions.CERT_INDEX1

        logger().info(f"Mapping certificate index->{cert_index} for socket_id->{sock}")
        wifi_dut.interfaces.wifi.set_socket_option(sock, SocketOptions.SOL_SOCKET, SocketOptions.SO_CERT_INDEX,
                                                   cert_index)

        logger().info(f"Binding socket with socket id:'{sock}'")
        wifi_dut.interfaces.wifi.bind(sock, device_ip, local_port)
        if sock_count == 0:
            wifi_dut.interfaces.wifi.connect_to_server(sock, ssl_server.interfaces.ssl, server_port=socket_port)
        else:
            result = wifi_dut.interfaces.wifi.dns_get(4)
            logger().info(f"dns response is {result}")
            aws_server_ip = result.split(b"\n")[1].split(b":")[1].decode()
            logger().info(f"aws_server_ip is:{aws_server_ip}")
            for count in range(3):
                try:
                    wifi_dut.interfaces.wifi.connect(sock, aws_server_ip, socket_port)
                    break
                except:
                    logger().info(f"Connecting to AWS server is failed. retry count->{count + 1}")
                    time.sleep(10)
                    if count == 2:
                        raise
            logger().info(f"Connection to AWS server on socket id->{sock} is successful")

    pkt_count = 10000
    buffer_length = 1370
    bytes_sent = (pkt_count * buffer_length)
    logger().info(f"\n\nSending data from DUT over ssl socket with socket id 0")
    ssl_server.interfaces.ssl.data_receive(1, pkt_count, buffer_length)
    wifi_dut.interfaces.wifi.send_data_pkts(0, buffer_length, pkt_count)
    time.sleep(10)
    bytes_received = ssl_server.interfaces.ssl.data_receive_stats(1)
    assert bytes_sent == bytes_received, "Number of bytes sent by DUT and received on the remote peer not matched on socket 0"

    send_bytes = 1000
    sw = Stopwatch()
    logger().info("\n\nSending data from DUT over ssl with socket id 1")
    while sw.elapsed_sec < 30:
        send_response = wifi_dut.interfaces.wifi.send(1, send_bytes)
        assert send_response, "Data transfer failed from socket id 1"
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")

    logger().info(f"\n\nWaiting for '60' seconds for checking connection stability")
    time.sleep(60)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    for sock in range(2):
        logger().info(f"\n\nClosing opend socket from DUT with socket_id->{sock}")
        result = wifi_dut.interfaces.wifi.close_socket(sock)
        assert b"success" in result, f"unable to close opened socket in the dut for socket_id->{sock}"
        logger().info(f"Successfully closed socket_id->{sock}")

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

    logger().info("Initiating BLE disconnection from Raspi")
    ble_client.interfaces.bluetooth.disconnect(ble_dut_address)

    logger().info("Initiating WLAN disconnection from DUT")
    wifi_dut.interfaces.wifi.leave()
