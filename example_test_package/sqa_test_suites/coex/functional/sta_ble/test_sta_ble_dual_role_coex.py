import time
import pytest
import random
import string
from utf.interfaces.wifi import WlanError
from utf.utils.thread_base import ThreadBase
from utf.utils.stopwatch import Stopwatch
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
from retry import retry
import subprocess

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
    status = wifi_dut.interfaces.wifi.join_ap(wifi_access_point, timeout=30)
    logger().info(f"wifi_join status: {status}")
    time.sleep(5)

    ip_fail = 1
    device_ip = None
    for count in range(5):
        try:
            result = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(result, wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {result}"
            device_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            ip_fail = 0
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
            time.sleep(15)
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
    time.sleep(5)

    status = False
    for count in range(5):
        try:
            logger().info("pinging to dut after power save.....")
            status = ping(device_ip, ping_count)
            assert status, "DUT not responding for ping request......"
            break
        except:
            logger().info(f"DUT not responding for ping request..retry count -> {count + 1}")
            time.sleep(15)
    assert status, "DUT not responding for ping request......"
    return device_ip


@retry(Exception, delay=15, tries=5)
def ble_master_slave(wifi_dut, ble_client, mode, ble_dut_address=None, start_needed=True, skip_scan=False,
                     secure_connect=False, expected="RSI_BLE_ENCRYPT_STARTED_EVENT"):
    ble_client_address = None
    if mode == "ble_master":
        try:
            if start_needed:
                logger().info(f"Set up DUT for BLE master role")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
                logger().info("Started BLE in DUT")
                assert ble_dut_address, f"failed to initiate ble in dut"
                time.sleep(3)
            logger().info("Start ble client")
            ble_client.interfaces.bluetooth.close()
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_adv(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"failed to initiate ble in remote device"
            time.sleep(5)
            if not skip_scan:
                logger().info("Start scanning and connect to ble client")
                wifi_dut.interfaces.wifi.ble_start_scanning(ble_client_address=ble_client_address, timeout=120)
                wifi_dut.interfaces.wifi.ble_stop_scanning()
        except Exception as e:
            try:
                logger().info("*************** Exception block for stop advertising and stop scanning ***************")
                ble_client.interfaces.bluetooth.stop_advertising()
                wifi_dut.interfaces.wifi.ble_stop_scanning()
            except:
                pass
            raise e
        logger().info("Initiating BLE connection with ble_client")
        wifi_dut.interfaces.wifi.ble_connect(ble_remote_dev_address=ble_client_address, expected=expected, timeout=120)
        time.sleep(2)
        logger().info("BLE master connection success")

    if mode == "ble_slave":
        try:
            if start_needed:
                logger().info(f"Set up DUT for BLE advertising")
                ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
                assert ble_dut_address, f"Unable to find ble dut address, failed to initiate ble in dut"
            wifi_dut.interfaces.wifi.ble_start_advertising()
            logger().info(f"Begin Scanning for BLE devices")
            ble_client.interfaces.bluetooth.close()
            ble_client_address = ble_client.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
            assert ble_client_address, f"failed to initiate ble in remote device"

            time.sleep(5)
            ble_client.interfaces.bluetooth.stop_scanning()
            found_devices = ble_client.interfaces.bluetooth.get_devices()
            logger().info(f"ble_scan_list:\n{found_devices}")
            assert wifi_dut.interfaces.wifi.ble_address in found_devices, "Unable to find our DUT"
            assert (found_devices[
                        wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
            logger().info(f"See that we found our device:'{ble_dut_address}'")
        except Exception as e:
            logger().info("*************** Exception block for stop advertising and stop scanning")
            wifi_dut.interfaces.wifi.ble_stop_advertising()
            ble_client.interfaces.bluetooth.stop_scanning()
            raise e
        logger().info("Initiating BLE Connection from ble_client")
        if secure_connect:
            connect_state = ble_client.interfaces.bluetooth.pair_and_connect(dev_addr=ble_dut_address, timeout=500)
            assert connect_state, "Unable to connect to DUT BLE from raspi"
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
        logger().info("BLE slave connection success")
    return ble_client_address, ble_dut_address


def run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=30):
    logger().info("Getting Host IP address")
    host_ip = wifi_client.interfaces.wifi.get_ip_address()
    logger().info(f"Host IP: {host_ip}")

    # starting iperf
    net_perf_client.interfaces.net_perf.init_server(host_ip=host_ip, device_ip=device_ip, protocol=protocol,
                                                    time_out=iperf_time)
    time.sleep(5)
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


def check_connection_status(wifi_dut, ble=False, wlan=False, ble_clients=None, ble_dut_address=None):
    if ble:
        logger().info("\n********************* Checking connection status of BLE from DUT ********************")
        state = wifi_dut.interfaces.wifi.ble_get_device_state()
        state_int = int(state) if state.isdigit() else -1
        assert state_int == BLEDeviceState.Connected, "DUT is not connected to remote BLE device"
        logger().info("\n***************** DUT is not disconnected from remote BLE device ********************")

        if ble_clients:
            for ble_client in ble_clients:
                logger().info(f"\n************ Checking connection status of BLE from '{ble_client.name}' ************")
                status = ble_client.interfaces.bluetooth.get_connection_status(ble_dut_address)
                logger().info(f"Connection status in remote device '{ble_client.name}' is:{status}")
                assert status, f"Remote device '{ble_client.name}' is not connected to DUT '{ble_dut_address}'"
                logger().info(f"\n********** '{ble_client.name}' still connected to DUT '{ble_dut_address}' **********")

    if wlan:
        logger().info("\n*********************** Checking connection status of Wi-Fi *************************")
        events = wifi_dut.interfaces.wifi.get_async_events()
        disconnect_events = [event for event in events if event.event_type == RS9116AsyncEventType.Disconnect]
        count_disconnect = set()
        if len(disconnect_events):
            count_disconnect.add(str(disconnect_events[0]))
            logger().info(f"Disconnect Events:{count_disconnect}")
            assert False, f"DUT is not connected to Wi-Fi"
        assert len(disconnect_events) == 0
        logger().info(f"\n**********************  DUT is not disconnected from Wi-Fi *************************")


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


@retry(Exception, delay=15, tries=5)
def ping_with_custom_size(device_ip, ping_counts=10, byte_size=64):
    command = ["ping", "-c", str(ping_counts), "-s", str(byte_size), device_ip]
    result = subprocess.run(command, capture_output=True)
    rc = result.returncode
    stdout = result.stdout.decode("utf-8")
    stderr = result.stderr.decode("utf-8")
    if rc != 0 or stderr:
        logger().info(f"{command} command exited with code {rc} with output {stderr}")
    else:
        logger().info(f"{command} command exited with code {rc} with output {stdout}")
    assert rc == 0 and stderr == "", "Failed to ping to DUT"
    return rc == 0 and stderr == ""


def dut_recovery(wifi_dut, error):
    recovery_error_codes = ['0xffffffe2', '0xffffffd5']
    for error_code in recovery_error_codes:
        if error_code in str(error):
            logger().info('******* Initiating DUT Recovery using Reset **********')
            wifi_dut.interfaces.wifi.reset()


def dut_clean_up(wifi_dut, ble_client_address=None):
    logger().info("\n\n ---------------------------- Cleaning UP the DUT -------------------------------")
    try:
        if ble_client_address:
            logger().info("BLE disconnect from DUT")
            try:
                wifi_dut.interfaces.wifi.ble_disconnect(ble_client_address)
            except:
                pass
        time.sleep(5)
        logger().info("Closing all sockets opened in DUT")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        time.sleep(5)
    except Exception as err:
        logger().info(
            f"******* Exception occurred while cleaning up the DUT\nException is:{err}\nRecovering the DUT using reset **********")
        wifi_dut.interfaces.wifi.reset()
        time.sleep(20)
    logger().info("\n ---------------------------- Cleaning UP of DUT is Completed -------------------")


pytestmark = [pytest.mark.ble_client("raspi_ble_client"),
              pytest.mark.ble_clients(["raspi_ble_client", "secondary_raspi_ble_client"]),
              pytest.mark.config("wifi_access_point", wifi={"channel": 4})]


# ##### DUAL ROLE PR1 ######
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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_wlan_data_transfer_after_ble_master_connection_along_with_advertise_C20201(wifi_dut, wifi_sniffer,
                                                                                    wifi_access_point, wifi_client,
                                                                                    ble_clients, net_perf_client,
                                                                                    protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    validation = True

    ble_mode = "ble_master"
    logger().info("Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True)

    try:
        logger().info("Start BLE advertising on DUT")
        wifi_dut.interfaces.wifi.ble_start_advertising()

        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file="Capture_C20201")
        time.sleep(3)

        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
            assert len(scan_results) > 0, "scan_list not found"
            logger().info(scan_results)
        logger().info(f"Scan in {t.duration} seconds")

        logger().info("Joining into Wi-Fi on DUT")
        device_ip = wifi_join(wifi_dut, wifi_access_point)
        time.sleep(2)

        logger().info(f"Initiating UDP traffic")
        run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)

        logger().info(f"Begin Scanning for BLE devices")
        ble_client2.interfaces.bluetooth.close()
        ble_client_address2 = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
        assert ble_client_address2 is not None, f"ble client address not found"
        time.sleep(5)
        ble_client2.interfaces.bluetooth.stop_scanning()
        found_devices = ble_client2.interfaces.bluetooth.get_devices()
        logger().info(f"ble_scan_list:\n{found_devices}")
        assert wifi_dut.interfaces.wifi.ble_address in found_devices, "Could not able to find our DUT"
        logger().info(f"See that we found our device:'{ble_dut_address}'")
    except Exception as e:
        logger().info("*************** Exception block for stop advertising and stop scanning ***************")
        ble_client2.interfaces.bluetooth.stop_scanning()
        wifi_dut.interfaces.wifi.ble_stop_advertising()
        raise e

    # ble_client2.interfaces.bluetooth.pair_and_connect(dev_addr=ble_dut_address)
    # time.sleep(2)
    # logger().info("BLE slave connection successful")

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

    logger().info("Initiating BLE disconnection from remote device--->MASTER")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(10)
    # logger().info("Initiating BLE disconnection from DUT--->MASTER")
    # wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1)


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan"])
def test_dual_role_verify_ble_master_first_and_slave_later_with_ping_C20267(wifi_dut, ble_clients, wifi_access_point,
                                                                            wifi_client, wifi_sniffer, rs_helper,
                                                                            utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")
    ble_client_address1 = None
    try:
        assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
        ble_client1 = ble_clients[1]
        ble_client2 = ble_clients[0]

        validation = True
        time_duration = utf_constants.get("time_duration")
        ping_counts = utf_constants.get("ping_count")
        channel = wifi_access_point.interfaces.wifi.channel
        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='Capture_C20267')
        time.sleep(3)

        with TimeMeasurer() as t:
            scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
            assert len(scan_results) > 0, "scan_list not found"
            logger().info(scan_results)
        logger().info(f"Scan in {t.duration} seconds")

        logger().info("Joining into Wi-Fi")
        device_ip = wifi_join(wifi_dut, wifi_access_point)
        time.sleep(2)

        ble_mode = "ble_master"
        logger().info(f"*** Initiating BLE test with DUT mode '{ble_mode}'")
        ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
        logger().info(f"*** BLE_MASTER CONNECTION SUCCESSFUL")

        ble_mode = "ble_slave"
        logger().info(f"+++ Initiating BLE test with DUT mode '{ble_mode}'")
        ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, secure_connect=True,
                                                  start_needed=False)

        logger().info(f"Initiating wlan ping with size '300' bytes for ping_counts:'{ping_counts}'")
        # status = rs_helper.ping_with_custom_size(device_ip, ping_counts, byte_size=300)
        status = ping_with_custom_size(device_ip, ping_counts, byte_size=300)
        assert status, "DUT not responding for ping request......"
        logger().info("ping to DUT is successful....")

        time_minutes = round((time_duration / 60), 2)
        logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
        time.sleep(time_duration)
        check_connection_status(wifi_dut, ble=True, wlan=True, ble_clients=ble_clients, ble_dut_address=ble_dut_address)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"Device mac address: {dut_mac_address}")
        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

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

        logger().info(f"Initiating Clean up after end of test steps")
        logger().info(f"Disconnect from Remote device which is Master")
        ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)
        time.sleep(10)
    except Exception as error:
        dut_recovery(wifi_dut, error)
        raise error
    finally:
        dut_clean_up(wifi_dut, ble_client_address1)


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
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_dual_role_verify_ble_slave_first_and_master_later_with_ping_C20268(wifi_dut, ble_clients, wifi_access_point,
                                                                            wifi_client, wifi_sniffer, rs_helper,
                                                                            utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    validation = True
    time_duration = utf_constants.get("time_duration")
    ping_counts = utf_constants.get("ping_count")
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='Capture_C20268')
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    time.sleep(2)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    ble_mode = "ble_slave"
    logger().info(f"+++ Initiating BLE SLAVE IN DUT FIRST '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
    logger().info(f"+++ BLE SLAVE CONNECTION SUCCESSFUL")

    ble_mode = "ble_master"
    logger().info(f"*** Initiating BLE MASTER  with DUT mode '{ble_mode}'")
    ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)
    logger().info(f"*** BLE_MASTER CONNECTION SUCCESSFUL")

    logger().info(f"Initiating wlan ping with size '300' bytes for ping_counts:'{ping_counts}'")
    # status = rs_helper.ping_with_custom_size(device_ip, ping_counts, byte_size=300)
    status = ping_with_custom_size(device_ip, ping_counts, byte_size=300)
    assert status, "DUT not responding for ping request......"
    logger().info("ping to DUT is successful....")

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True, ble_clients=ble_clients, ble_dut_address=ble_dut_address)

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

    logger().info(f"Disconnect from Remote device which is Master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(10)
    # logger().info(f"Disconnect from DUT Master")
    # wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address2, timeout=30)


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
@pytest.mark.config("net_perf_client", net_perf={"host_role": IperfConstants.SERVER_MODE})
@pytest.mark.parametrize("protocol", [IperfConstants.UDP])
@pytest.mark.end_state("wifi_dut",
                       wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated", "ble_stop_adv",
                             "ble_stop_scan", "ble_disconnect"])
def test_dual_role_wlan_udp_rx_data_transfer_C20271(wifi_dut, wifi_sniffer, wifi_access_point, net_perf_client,
                                                    wifi_client, ble_clients, protocol, utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[1]
    ble_client2 = ble_clients[0]

    validation = True
    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='Capture_C20271')
    time.sleep(3)

    with TimeMeasurer() as t:
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None, channel=channel)
        assert len(scan_results) > 0, "scan_list not found"
        logger().info(scan_results)
    logger().info(f"Scan in {t.duration} seconds")

    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    time.sleep(2)

    logger().info(f"Start BLE in DUT")
    ble_dut_address = wifi_dut.interfaces.wifi.ble_start()
    assert ble_dut_address, "Unable to find ble dut address, failed to initiate ble in dut"

    logger().info("++++ Initiating BLE SLAVE IN DUT FIRST")
    wifi_dut.interfaces.wifi.ble_start_advertising()
    time.sleep(3)
    logger().info("Begin Scanning for BLE devices")
    ble_client2.interfaces.bluetooth.close()
    ble_client_address2 = ble_client2.interfaces.bluetooth.start_smp_scan(bt_dut_address=ble_dut_address)
    assert ble_client_address2, "failed to initiate ble in remote device"
    time.sleep(5)
    ble_client2.interfaces.bluetooth.stop_scanning()
    found_devices = ble_client2.interfaces.bluetooth.get_devices()
    logger().info(f"ble_scan_list:\n{found_devices}")
    assert wifi_dut.interfaces.wifi.ble_address in found_devices, "Unable to find our DUT"
    assert (found_devices[
                wifi_dut.interfaces.wifi.ble_address] == wifi_dut.interfaces.wifi.ble_advertising_data), "Could not able to find our DUT"
    logger().info(f"See that we found our device:'{ble_dut_address}'")
    time.sleep(3)
    ble_client2.interfaces.bluetooth.connect(dev_addr=ble_dut_address, min_conn_interval=20, max_conn_interval=20,
                                             supervision_timeout=200)
    time.sleep(2)
    logger().info("BLE slave connection success")

    ble_mode = "ble_master"
    logger().info(f"##### Initiating BLE MASTER  with DUT mode '{ble_mode}'")
    ble_client_address1, _ = ble_master_slave(wifi_dut, ble_client1, ble_mode, ble_dut_address, start_needed=False)
    logger().info(f"*** BLE_MASTER CONNECTION SUCCESSFUL")

    logger().info(f"Initiating UDP traffic")
    run_iperf_server(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True, ble_clients=ble_clients, ble_dut_address=ble_dut_address)

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

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

    logger().info(f"Initiating Clean up after end of test steps")
    logger().info(f"Disconnect from Remote device which is Master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(10)
    # logger().info(f"Disconnect from DUT Master")
    # wifi_dut.interfaces.wifi.ble_disconnect(ble_remote_dev_address=ble_client_address1, timeout=30)


# ################################# PR2 ############################################
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20349', "security": "WPA2"})
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
def test_dual_role_verify_scan_join_and_data_transfer_functionality_of_dut_sta_when_ble_in_connection_C20349(wifi_dut,
                                                                                                             wifi_sniffer,
                                                                                                             wifi_access_point,
                                                                                                             ble_clients,
                                                                                                             net_perf_client,
                                                                                                             wifi_client,
                                                                                                             protocol,
                                                                                                             utf_constants):
    if not isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
        raise NotImplementedError("This test case is only currently implemented for SAPI")

    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]

    time_duration = utf_constants.get("time_duration")
    channel = wifi_access_point.interfaces.wifi.channel
    validation = True

    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)

    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)

    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file="Capture_C20349")
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

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(10)

    logger().info(f"Checking connection status, when data transfer is in progress")
    check_connection_status(wifi_dut, ble=True, wlan=True, ble_clients=ble_clients, ble_dut_address=ble_dut_address)
    t1.wait_for_exit(True)

    time_minutes = round((time_duration / 60), 2)
    logger().info(f"Waiting for '{time_minutes}' minutes for checking connection stability")
    time.sleep(time_duration)
    check_connection_status(wifi_dut, ble=True, wlan=True, ble_clients=ble_clients, ble_dut_address=ble_dut_address)

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

    logger().info("Initiating BLE disconnection from remote device which is master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(10)


@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'test_C20332', "security": "WPA2"})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.ULPGPIOHandshake,
        "tcpip_features": RS9116TCPIPFeatureBitMap.Default,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose,
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
def test_sta_ble_datatransfer_in_dualrole_C20332(wifi_dut, wifi_access_point, wifi_sniffer, net_perf_client,
                                                 wifi_client, protocol, ble_clients, ble_client):
    logger().info("**************testcase : C20332*******************")
    channel = wifi_access_point.interfaces.wifi.channel
    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    validation = True
    wifi_sniffer.interfaces.capture.start_capture(capture_file="wifi data transfer in the ble dual role")
    assert len(ble_clients) >= 2, f"Minimum 2 Raspi devices needed"
    ble_client1 = ble_clients[0]
    ble_client2 = ble_clients[1]
    logger().info("Joining into Wi-Fi")
    device_ip = wifi_join(wifi_dut, wifi_access_point)
    t1 = wifi_traffic_thread(net_perf_client, wifi_dut, wifi_client, protocol, device_ip, iperf_time=100)
    t1.start()
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"Device mac address: {dut_mac_address}")
    time.sleep(10)
    ble_mode = "ble_master"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address1, ble_dut_address = ble_master_slave(wifi_dut, ble_client1, ble_mode)
    ble_mode = "ble_slave"
    logger().info(f"Initiating BLE test with DUT mode '{ble_mode}'")
    ble_client_address2, _ = ble_master_slave(wifi_dut, ble_client2, ble_mode, ble_dut_address, start_needed=False)
    check_connection_status(wifi_dut, ble=True, wlan=True, ble_clients=ble_clients, ble_dut_address=ble_dut_address)
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

    logger().info("Initiating BLE disconnection from remote device which is master")
    ble_client2.interfaces.bluetooth.disconnect(ble_dut_address)
    time.sleep(10)
