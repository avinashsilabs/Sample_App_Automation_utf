import re
import time
from datetime import datetime, timedelta
from utf.utils.iperf.iperf_utils import print_dict, ping
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.wifi import WlanError, SecurityMode
from utf.utils.logger import get_logger
from utf.utils.thread_base import ThreadBase
from utf.interfaces.cli import CLITransportException
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, RS9116Band,  \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116ExtCustomFeatureBitMap, RS9116JoinFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116PowerSaveProcedureTypes, RS9116CustomFeatureBitMap,
)
from utf.utils.stopwatch import Stopwatch


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This function runs below test steps for DUT-RS9116 for Rejoin test case verification
        1. Configuration of DUT in 5G 
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number and send data.
        7. Disable the AP radio and check unicast Probe request packet in sniffer after some time it should start 
           broadcast probe request packet
        8. verify rejoin & probe request packet with different security, different channels, and for different region(US/UK/worldwide)
        9. Japan region doesn't support in ASUS AP so need to implement or use another AP. 

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
"""


class FilterPacket:
    def delta_between_probe_packet(self):
        packet_filter = "Time delta from previous captured frame"
        count = 0
        time_diff = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()

        for x in line:
            count = count + 1
            if packet_filter in x:
                time_delta_from_previous_packet = line[count].strip().split(':')[1].replace(']', '').strip().replace(
                    'seconds', '')
                logger().info(f'time_delta_from_previous_packet={time_delta_from_previous_packet}')
                time_diff.append(float(time_delta_from_previous_packet))

        logger().info(time_diff)
        filter_file.close()
        return time_diff


class IopTcpIpSockets:
    def open_socket(self, wifi_dut, dut_ip) -> int:
        if isinstance(wifi_dut.interfaces.wifi, RSSAPICommands):
            tcp_socket_id = wifi_dut.interfaces.wifi.open_tcp_client_socket()
            if isinstance(tcp_socket_id, int):
                logger().info(f"Socket open successfully : {tcp_socket_id}")
            else:
                logger().error(f"Unable to open socket id: {tcp_socket_id}")
                raise RuntimeError(tcp_socket_id)

            time.sleep(2)
            bind_response = wifi_dut.interfaces.wifi.bind(tcp_socket_id, dut_ip)
            if bind_response.decode().split(">")[1].replace("'", '').strip() == 'success':
                logger().info(f"Bind socket successfully: {bind_response}")
            else:
                logger().error(f"Unable to bind socket: {bind_response}")
                raise RuntimeError(bind_response)
        return tcp_socket_id

    def connect_socket(self, wifi_dut, tcp_socket_id: int):
        retry_limit: int = 2
        connect_status = False
        for retry in range(1, retry_limit):
            connect_response = wifi_dut.interfaces.wifi.connect(tcp_socket_id)
            logger().info(f"Connect response : {connect_response}")
            if connect_response.decode() == '':
                logger().info(f"Unable to connect socket: {connect_response} in {retry} try")
                if retry < retry_limit:
                    pass
            elif connect_response.decode().split(">")[1].strip() == 'success':
                logger().info(f"Socket connected successfully in {retry} try")
                connect_status = True
                break
            logger().info(f"Socket connected with server in: {retry + 1} time")
        return connect_status


class WifiPingThread(ThreadBase):
    def __init__(self, wifi_dut, device_ip):
        super().__init__()
        self.device_ip = device_ip

    def run(self):
        # Initiate ping from third party wifi-client to DUT
        logger().info(f'\n\n Ping traffic is going on for 300 sec ........Please wait\n')
        ping(self.device_ip, 300)


class AccessPointApOnOff(ThreadBase):
    def __init__(self, switch):
        super().__init__()
        self.switch = switch

    def run(self):
        logger().info('\n\n******* Turn on Access point **********\n')
        self.switch.interfaces.pdu_switch.turn_on(delay=90)
        logger().info('\n\n******* Wait for 90 second after turn on the AP radio **********\n')
        logger().info('\n\n ******* Turn off the AP radio **********\n')
        self.switch.interfaces.pdu_switch.turn_off(10)


def clean_up_method(wifi_dut, switch):
    logger().info("\n\n ----------------------------Cleaning UP the DUT ----------------------------")
    try:
        logger().info('******* Turn on Access point Finally **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        logger().info("Closing all opened sockets")
        wifi_dut.interfaces.wifi.close_sockets()
        logger().info("Disconnect from AP")
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
    except:
        logger().info("******* Recovering the DUT  **********")
        wifi_dut.interfaces.wifi.reset()
    logger().info("\n ----------------------------Cleaning UP of DUT is Completed ----------------------------")



pytestmark = [
    pytest.mark.start_state("wifi_dut", wifi="init"),
    pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled"),
    pytest.mark.start_state("wifi_access_point", wifi="ap_enabled"),
    pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "close_sockets"])
]


@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": RS9116Band.FiveGHz,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_c19391(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):

    try:
        '''configure the 5ghz channel bitmap position to zero and Check our DUT is sending the broadcast Probe
        requests in all 5ghz channels or not when the connected AP is turned OFF'''
        validation = True
        channel_list = {0: 36, 1: 40, 2: 44, 3: 48, 19: 149, 20: 153, 21: 157, 22: 161, 23: 165}
        channel_bitmap_5 = 0
        channel_bitmap_2_4 = 0
        scan_feature_extend = 0
        probe_not_captured_channel_list = []
        probe_check_dict = {}
        for count in channel_list:
            channel_bitmap_5 += 1 << count
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_All_channels_c19723')
        logger().info("Initiating the selective channel scan in dut...")
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                       scan_bitmap_2_4=channel_bitmap_2_4,
                                                                       scan_bitmap_5=channel_bitmap_5,
                                                                       scan_feature=scan_feature_extend)
        time.sleep(5)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "Scan results not found"

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info(f"***** preparing wifi_dut ******")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point, channel=0)

        ip_config = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)

        logger().info(f"*****Initiating Power_save Mode2 in DUT******")
        logger().info("Enabling wifi power save")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "failed to enable wifi power save"

        logger().info("Enabling bt power save")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "failed to enable bt power save"

        logger().info(f"Initiating ping to DUT ip {dut_ip} after power save")
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=10)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list.values()}\n\n")
        for channel in channel_list.values():
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f'(wlan_radio.channel == {channel} ' \
                             f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and ' \
                             f'(wlan.sa == {dut_mac_address})'

            output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count']
            probe_check_dict[channel] = int(output)

        logger().info(f'\n\n ***** probe check dictionary : {probe_check_dict} ***** \n\n')
        for key, value in probe_check_dict.items():
            if value == 0:
                probe_not_captured_channel_list.append(key)

        logger().info(f"probe not captured channel list: {probe_not_captured_channel_list}")
        assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
        logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


@pytest.mark.parametrize("change_security_mode_startup_time, change_security_mode", [('WPA2', 'Open')])
@pytest.mark.config('wifi_access_point', wifi={"channel": 149})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.
        FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3 |
        RS9116ExtCustomFeatureBitMap.IEEE802_11W,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 1,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_max_retry_failure_with_security_mode_change_c19392(wifi_sniffer, wifi_access_point, wifi_dut,
                                                                   change_security_mode_startup_time,
                                                                   change_security_mode, switch):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    rejoin_value = 4

    '''Verify rejoin functionality by changing connected AP security settings in 5Ghz'''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)
    security_mode_startup = f'SecurityMode.{change_security_mode_startup_time}'
    logger().info(f'\n\n ***** Security mode configured in {change_security_mode_startup_time} *****\n\n')
    wifi_access_point.interfaces.wifi.start_ap(security=eval(security_mode_startup))
    time.sleep(10)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    if change_security_mode_startup_time == 'WPA3':
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point,
                                         join_feature_bitmap=RS9116JoinFeatureBitMap.MgmtFrameProtectionCapable
                                                             | RS9116JoinFeatureBitMap.MgmtFrameProtectionRequired,
                                         timeout=25)
    else:
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {dut_ip}")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable bt power save"

    packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                     f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
    time.sleep(2)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        logger().info(f'SEND-RESPONSE = {send_response}')
        if 'status 10' in str(send_response):
            result = send_response.decode().replace("\r\n", '').strip()
            match = re.findall(r"\d+", result)
            if int(match[1]) == send_bytes:
                logger().info(f"Send {send_bytes} bytes successfully")
        else:
            logger().info(f"Data transfer failed")
            assert send_response

    wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_max_retry_failure')
    time.sleep(2)
    end_time = datetime.now() + timedelta(minutes=2)

    security_mode = f'SecurityMode.{change_security_mode}'
    logger().info(
        f'\n\n***** Change the security mode from {change_security_mode_startup_time} to {security_mode} *****\n\n')

    wifi_access_point.interfaces.wifi.start_ap(security=eval(security_mode))
    time.sleep(15)

    """validate rejoin retry failure"""
    while datetime.now() < end_time:
        events = wifi_dut.interfaces.wifi.get_async_events()
        rejoin_error_events = [event for event in events if
                               event.event_type == RS9116AsyncEventType.RejoinError]
        if len(rejoin_error_events):
            logger().info(f'RE-JOIN ERROR = {rejoin_error_events}')
            break

    wifi_dut.interfaces.wifi.associated = False
    wifi_dut.interfaces.wifi.leave()
    wifi_sniffer.interfaces.capture.stop_capture()

    try:
        packet_count = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['find_packet_num']

        if (int(packet_count) + 1) == rejoin_value:
            logger().info(
                f"\n\nSuccessfully matched broadcast probe request packet count = {rejoin_value} is equal to one less "
                f"sniffer packet "
                f"count = {packet_count}\n\n")
            assert True
        else:
            logger().info(f"Failed, broadcast probe request packet count = {rejoin_value} is not equal to one less "
                          f"sniffer "
                          f"packet "
                          f"count = {packet_count}")
            assert False
    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config('wifi_access_point', wifi={"channel": 48})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost |RS9116CustomFeatureBitMap.DualBandRoamingAndVcafd,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 2,
    },
)
@pytest.mark.wifi_dualband
def test_rejoin_dual_band_c19393(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    try:
        '''configure the 2.4Ghz and 5ghz channel bitmap positions to zero with dual band configuration and Check our
        DUT is sending the broadcast Probe requests in all 2.4Ghz and 5Ghz channels or not when the connected AP is turned OFF'''
        validation = True
        channel_list_5g = {0: 36, 1: 40, 2: 44, 3: 48, 19: 149, 20: 153, 21: 157, 22: 161, 23: 165}
        channel_list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165]
        probe_not_captured_channel_list = []
        probe_check_dict = {}
        channel_bitmap_5 = 0
        channel_bitmap_2_4 = 0
        scan_feature_extend = 0
        for channel in channel_list:
            if channel == 36:
                break
            else:
                channel_bitmap_2_4 += 1 << (channel - 1)

        for count in channel_list_5g:
            channel_bitmap_5 += 1 << count

        '''Rejoin functionality when dual band selected'''
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)
        ping_count = utf_constants.get("ping_count")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_All_channels_c19393')
        logger().info("Initiating the selective channel scan in dut...")
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                       scan_bitmap_2_4=channel_bitmap_2_4,
                                                                       scan_bitmap_5=channel_bitmap_5,
                                                                       scan_feature=scan_feature_extend)
        time.sleep(5)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "Scan results not found"

        logger().info(f"***** preparing wifi_dut ******")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point, channel=0)

        ip_config = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip address : {dut_ip}")

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        logger().info(f"*****Enable Max PSP in DUT******")
        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"
        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"

        logger().info(f"Initiating ping to DUT ip {dut_ip} after power save")
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=60)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list}\n\n")
        for channel in channel_list:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f'(wlan_radio.channel == {channel} ' \
                             f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and ' \
                             f'(wlan.sa == {mac_address})'

            output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count']
            probe_check_dict[channel] = int(output)

        logger().info(f'\n\n ****** probe check dictionary : {probe_check_dict} ****** \n\n')
        for key, value in probe_check_dict.items():
            if value == 0:
                probe_not_captured_channel_list.append(key)

        logger().info(f"probe not captured channels: {probe_not_captured_channel_list}")
        assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
        logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
                raise e
    finally:
        clean_up_method(wifi_dut, switch)


@pytest.mark.config('wifi_access_point', wifi={"channel": 52})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower,
        "band": 1,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_dfs_channel_c19394(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):

    validation = True

    '''Verify rejoin functionality in DFS channels '''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)
    time.sleep(90)
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    ping_count = utf_constants.get("ping_count")
    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')
    # Added verification if AP will not beaconing in DFS channel, program will terminate
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='verify_beacon')
    time.sleep(5)
    wifi_sniffer.interfaces.capture.stop_capture()
    packet_filter1 = f'(radiotap.channel.freq == 5260) and (wlan.ta == {ap_bssid}) ' \
                     f'and wlan.fc.type_subtype == 0x0008'

    try:
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Beacon packets'

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ip_config = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip address : {dut_ip}")

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        logger().info(f"*****Enable Max PSP in DUT******")
        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")
        # Broadcast Probe request packet
        packet_filter2 = f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == ' \
                         f'{mac_address})'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)

        file_name = f'5g_uni_broad_prob_req'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
        logger().info('***** Disable the AP radio *****')
        switch.interfaces.pdu_switch.turn_off(10)
        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter2)['packet_count'], \
            'Unable to find Unicast Probe request packet'
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        time.sleep(60)
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device after the succesful rejoin"
        logger().info(f"ping after rejoin is successful")

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()

    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)


@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
@pytest.mark.parametrize("set_region_ap, set_region_dut", [('US', 1), ('Europe', 2), ('Japan', 3), ('world', 4)])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 1,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_different_region_non_dfs_c19395(wifi_sniffer, wifi_access_point, wifi_dut, set_region_ap,
                                                set_region_dut, switch, utf_constants):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    end_time = utf_constants.get("time_duration")
    '''Verify Rejoin Functionality with different regions enabled in 5GHZ band with non DFS channels US, EU, JP &
       world mode'''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)

    wifi_dut.interfaces.wifi.set_region(region=1, region_code=set_region_dut, module_type=1)
    logger().info(f'Setting the country region in AP ={set_region_ap} & DUT ={set_region_dut}')

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {dut_ip}")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable bt power save"

    packet_filter3 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                     f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
            logger().info(f'SEND-RESPONSE = {send_response}')
            if 'status 10' in str(send_response):
                result = send_response.decode().replace("\r\n", '').strip()
                match = re.findall(r"\d+", result)
                if int(match[1]) == send_bytes:
                    logger().info(f"Send {send_bytes} bytes successfully")
            else:
                logger().info(f"Data transfer failed")
                assert send_response

    file_name = f'5g_uni_broad_prob_req_{set_region_ap}'
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)

    logger().info('***** Disable the AP radio *****')
    switch.interfaces.pdu_switch.turn_off(delay=10)
    time.sleep(6)
    wifi_sniffer.interfaces.capture.stop_capture()

    try:
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='5g_rejoin')

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                else:
                    logger().info(f"Data transfer failed")
                    assert send_response

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        wifi_dut.interfaces.wifi.leave()

    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"channel": 64})
@pytest.mark.parametrize("set_region_ap, set_region_dut", [('US', 1), ('Europe', 2), ('Japan', 3), ('world', 4)])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.DFSChannelPassiveScan | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.BTFeatureBitmapValid | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode | RS9116ExtCustomFeatureBitMap.FeatureLowPower,
        "band": 1,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_different_region_dfs_ch_c19396(wifi_sniffer, wifi_access_point, wifi_dut, set_region_ap,
                                               set_region_dut, switch,utf_constants):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    end_time = utf_constants.get("time_duration")
    '''	Verify Rejoin Functionality with different regions enabled in 5GHZ band with DFS channels US, EU, JP & world
    mode'''
    '''Please note - ASUS AP does not support Japan region so I removed the japan region entry '''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)
    time.sleep(90)
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=set_region_dut, module_type=1)

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    time.sleep(10)
    try:

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

        ip_config = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip address : {dut_ip}")

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        logger().info(f"*****Enable Max PSP in DUT******")
        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"

        packet_filter1 = f'wlan.fc.type_subtype == 0x0004 and !(wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        file_name = f'5g_uni_broad_prob_req_{set_region_ap}'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                else:
                    logger().info(f"Data transfer failed")
                    assert send_response

        logger().info('***** Disable the AP radio *****')
        logger().info('******* Turn off Access point **********')
        switch.interfaces.pdu_switch.turn_off(delay=20)

        wifi_sniffer.interfaces.capture.stop_capture()
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Unicast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        file_name_rejoin = f'5G_Rejoin_{set_region_ap}'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name_rejoin)

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                else:
                    logger().info(f"Data transfer failed")
                    assert send_response

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()

    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_dut.interfaces.wifi.leave()


@pytest.mark.config('wifi_access_point', wifi={"channel": 48})
@pytest.mark.parametrize("set_region_ap, set_region_dut", [('US', 1), ('Europe', 2), ('Japan', 3), ('Asia', 4)])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 2,
    },
)
@pytest.mark.wifi_dualband
def test_rejoin_different_region_dual_band_non_dfs_c19398(wifi_sniffer, wifi_access_point, wifi_dut, set_region_ap,
                                                          set_region_dut, switch, utf_constants):
    tcp_socket_obj = IopTcpIpSockets()
    send_bytes = 1000
    validation = True
    end_time = utf_constants.get("time_duration")
    '''Verify Rejoin Functionality with different regions enabled in Dual band US, EU, JP & world mode'''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)

    # Set the region value in DUT side
    wifi_dut.interfaces.wifi.set_region(region=1, region_code=set_region_dut, module_type=1)
    logger().info(f'Setting the country region in AP ={set_region_ap} & DUT ={set_region_dut}')

    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_dut.interfaces.wifi.join_ap(wifi_access_point)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {dut_ip}")

    mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable bt power save"

    packet_filter3 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                     f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'

    tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
    time.sleep(5)
    connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
    if connect_status is False:
        logger().info("Unable to connect with Server")
        assert connect_status
    else:
        sw = Stopwatch()
        while sw.elapsed_sec < end_time:
            send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
            logger().info(f'SEND-RESPONSE = {send_response}')
            if 'status 10' in str(send_response):
                result = send_response.decode().replace("\r\n", '').strip()
                match = re.findall(r"\d+", result)
                if int(match[1]) == send_bytes:
                    logger().info(f"Send {send_bytes} bytes successfully")
            else:
                logger().info(f"Data transfer failed")
                assert send_response

    file_name = f'5g_uni_broad_prob_req_{set_region_ap}'
    wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)

    logger().info('***** Disable the AP radio *****')
    switch.interfaces.pdu_switch.turn_off(delay=10)
    time.sleep(6)
    wifi_sniffer.interfaces.capture.stop_capture()

    try:
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.start_capture(capture_file='5g_rejoin')

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if 'status 10' in str(send_response):
                    result = send_response.decode().replace("\r\n", '').strip()
                    match = re.findall(r"\d+", result)
                    if int(match[1]) == send_bytes:
                        logger().info(f"Send {send_bytes} bytes successfully")
                else:
                    logger().info(f"Data transfer failed")
                    assert send_response

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(5)
        wifi_dut.interfaces.wifi.leave()

    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)


@pytest.mark.config('wifi_access_point', wifi={"channel": 165})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 1,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_selected_channels_c43023(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):

    try:
        validation = True

        '''Check rejoin is happening or not when select channel as 36,48,165'''

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        channel_dict = {0: 36, 3: 48, 23: 165}
        probe_check_dict = {}
        channel_bitmap_5 = 0
        probe_not_captured_channel_list = []
        scan_feature_extend = 0

        for count in channel_dict:
            channel_bitmap_5 += 1 << count

        ping_count = utf_constants.get("ping_count")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='c43023_basic_association')

        logger().info("Initiating selective channel scan...")
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                       scan_bitmap_2_4=0,
                                                                       scan_bitmap_5=channel_bitmap_5,
                                                                       scan_feature=scan_feature_extend)
        logger().info(scan_results)
        assert len(scan_results) >= 1, "failed to scan...."

        wifi_dut.interfaces.wifi.join_ap(wifi_access_point, channel=0)

        ip_config = wifi_dut.interfaces.wifi.start_ip()
        dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
        logger().info(f"DUT ip address : {dut_ip}")

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        logger().info(f"*****Enable Max PSP in DUT******")
        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"
        logger().info(f"Initiating ping to DUT ip {dut_ip} after power save")
        status = ping(dut_ip, ping_count)
        assert status is True, "DUT is not responding to ping request from third party device"
        logger().info(f"ping is successful")

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=60)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info(f"\n\n Broadcast Probe request packet validation is start for channel = {channel_dict.values()}\n\n")
        for channel in channel_dict.values():
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(10)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f'(wlan_radio.channel == {channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and ' \
                         f'(wlan.sa == {dut_mac_address})'

            output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                    'packet_count']
        probe_check_dict[channel] = int(output)
        logger().info(f'\n\n ***** probe check dictionary : {probe_check_dict} ***** \n\n')
        for key, value in probe_check_dict.items():
            if value == 0:
                probe_not_captured_channel_list.append(key)

        logger().info(f"probe not captured channels: {probe_not_captured_channel_list}")
        assert probe_not_captured_channel_list == [], f"probe not captured channel list: {probe_not_captured_channel_list}"
        logger().info(f"probe requests are captured in all the configured channels, Hence the test case is PASS")

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


@pytest.mark.config('wifi_access_point', wifi={"channel": 36})
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "band": 1,
    },
)
@pytest.mark.wifi_5g
def test_rejoin_only_channels_36_c43022(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    validation = True
    channel = 36
    channel_dict = {0: 36}
    channel_bitmap_5 = 0
    scan_feature_extend = 0

    for count in channel_dict:
        channel_bitmap_5 += 1 << count

    '''Check rejoin is happening or not when select channel as 36'''
    logger().info('******* Turn on Access point **********')
    switch.interfaces.pdu_switch.turn_on(delay=60)
    ping_count = utf_constants.get("ping_count")
    wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

    wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
    time.sleep(2)
    wifi_sniffer.interfaces.capture.start_capture(capture_file='c43022_basic_association')

    logger().info("Initiating channel scan only in 36 ...")
    scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                   scan_bitmap_2_4=0,
                                                                   scan_bitmap_5=channel_bitmap_5,
                                                                   scan_feature=scan_feature_extend)
    logger().info(scan_results)
    assert len(scan_results) >= 1, "failed to scan...."

    wifi_dut.interfaces.wifi.join_ap(wifi_access_point, channel=channel)

    ip_config = wifi_dut.interfaces.wifi.start_ip()
    dut_ip = wifi_dut.interfaces.wifi.get_device_ip(ip_config)
    logger().info(f"DUT ip address : {dut_ip}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    logger().info(f"*****Enable Max PSP in DUT******")
    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable bt power save"

    time.sleep(5)
    # validate broadcast probe request packet
    packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                     f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {dut_mac_address})'
    # validate NULL data frame with PM bit set to '1'

    packet_filter3 = f' (wlan.fc.pwrmgt == 1) and ((wlan.fc.type_subtype == 0x0024) and (wlan.sa == {dut_mac_address}) ' \
                     f'and (wlan.da == {ap_bssid}))'

    wifi_sniffer.interfaces.capture.stop_capture()

    try:
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find Null data packet with PM bit 1'
        time.sleep(2)

        wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
        time.sleep(2)
        file_name = f'5g_broad_prob_req_for_ch_{channel}'
        wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)

        wlan_obj = WifiPingThread(wifi_dut, dut_ip)
        ap_obj = AccessPointApOnOff(switch)

        wlan_obj.start()
        ap_obj.start()
        wlan_obj.wait_for_exit()
        ap_obj.wait_for_exit()

        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"\n\n*****Sniffer validation for rejoin broadcast probe request ******\n")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        if wifi_dut.interfaces.wifi.associated is True:
            logger().info(f"Initiating ping to DUT ip {dut_ip} after successful rejoin")
            status = ping(dut_ip, ping_count)
            assert status is True, "DUT is not responding to ping request from third party device"
            logger().info(f"ping is successful")

        wifi_dut.interfaces.wifi.leave()

    except (AssertionError, IndexError, CLITransportException):
        assert False, 'Find exception'
    finally:
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
