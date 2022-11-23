import re
import time
from utf.utils.iperf.iperf_utils import ping
from retry import retry
from utf import UtfDatabaseProperties
from utf_wiseconnect.devices.rs911x import (RS9116CoexMode, RS9116PowerSaveModes, RS9116FeatureBitMap,
                                            RS9116CustomFeatureBitMap,
                                            RS9116ConfigFeatureBitMap,
                                            RS9116TCPIPFeatureBitMap,
                                            RS9116ExtCustomFeatureBitMap,
                                            RS9116ExtTCPIPFeatureBitMap,
                                            RS9116CertificateType,
                                            RS9116SecurityMode, RS9116PowerSaveProcedureTypes, RS9116JoinFeatureBitMap,
                                            RS9116RegionCode, SocketOptions, SocketType
                                            )
import pytest as pytest
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.interfaces.wifi import WlanError, SecurityMode
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116OperatingMode
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
)
from utf.utils.stopwatch import Stopwatch
from utf.interfaces.shell.ssh_shell import SSHShell


def logger():
    return get_logger(__name__)


"""Author : Vivek"""

"""This function runs below test steps for DUT-RS9116 for Rejoin test case verification
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket 
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number and send data.
        7. Turn off Access point and check unicast Probe request packet in sniffer after some time it should start 
           broadcast probe request packet
        8. verify rejoin & probe request packet with different security, different channels, and for different region(US/UK/Japan) 
        9. Note: TC - 19724 is duplicate, TC-19726/27/28 current UTF implementation doesn't support.
           TC-19730/31/32 are depend on TLS/TTLS/PEAP
        

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)
        
      Modified by CG team : Considered PDU fix [UTF-1660 and updated the code]
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

            time.sleep(5)
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


def wifi_join(wifi_dut, wifi_access_point, ping_count=10):
    logger().info(f"Initiating wlan join from DUT")
    for i in range(3):
        try:
            wifi_dut.interfaces.wifi.associated = False
            wifi_dut.interfaces.wifi.scan(ssid=None, channel=wifi_access_point.interfaces.wifi.channel)
            time.sleep(3)
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
            time.sleep(5)
            break
        except Exception as e:
            logger().info(f"Error found:{str(e)} ----> Count{i} ")
            if "0x2" in str(e):
                logger().info(
                    f"Error found:{str(e)} ----> Device already in connected step need to disconnect before connect")
                logger().info("Initiating disconnect for cleanup")
                wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                wifi_dut.interfaces.wifi.associated = False
                time.sleep(5)
            if i == 2:
                raise e

    dut_ip = None
    for count in range(1, 4):
        try:
            ip_config = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(ip_config,
                              wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            break
        except:
            logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
            time.sleep(10)
    assert dut_ip, "ip setting in DUT has failed"
    logger().info(f'DUT ip {dut_ip}')

    logger().info("Initiating wlan power save on DUT")
    enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                         RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_wifi_ps, "Failed to enable wifi power save"

    logger().info("Initiating bt power save on DUT")
    enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                          RS9116PowerSaveProcedureTypes.FastPowerSave)
    assert enable_bt_ps, "Failed to enable bt power save"
    logger().info("*****Enabled ENH Max PSP in DUT******")

    status = False
    for count in range(5):
        try:
            logger().info("pinging to dut after power-save.....")
            status = ping_to_dut(dut_ip, ping_count)
            logger().info("ping to DUT is successful....")
            break
        except:
            logger().info(f"ping to dut is failed...retry count->{count + 1}")
            time.sleep(15)
    assert status, "DUT not responding for ping request......"
    return dut_ip


def delta_btwn_last_beacon_and_first_probe_req(wifi_sniffer, dut_mac_address, ap_bssid, test_case):
    """ Method to calculate time stamp for the last beacon and consecutive broadcast and unicast probe request"""
    remote_capture_file = wifi_sniffer.interfaces.capture.remote_capture_file
    logger().info(f"capture file is:{remote_capture_file}")

    filter_files = "/tmp/filter_files"
    filtered_file = f'{filter_files}/{test_case}_main_filter.pcap'
    wifi_sniffer.interfaces.capture.shell(
        f"sudo rm -rf {filter_files}; sudo mkdir {filter_files}; sudo chmod +777 {filter_files};")

    filter1 = f'tshark -r {remote_capture_file} -Y "(wlan.addr eq {dut_mac_address}) or (wlan.addr eq {ap_bssid})" -w {filtered_file}'
    logger().info("Creating filtered packets")
    wifi_sniffer.interfaces.capture.shell(filter1)

    logger().info("Getting last beacon from the filtered file")
    filter2 = f'tshark -r {filtered_file} -Y "wlan.fc.type_subtype eq 8" -Tfields -e "wlan.fc.type_subtype" -e "frame.time" -e "frame.time_relative" | tail -1'
    last_beacon_time = float(wifi_sniffer.interfaces.capture.shell(filter2)[1].split()[-1])
    logger().info(f"last_beacon_time: {last_beacon_time} seconds")

    logger().info("Getting uni-cast probe_requests from the filtered file")
    filter3 = f'tshark -r {filtered_file} -Y "(wlan.fc.type_subtype eq 4 && wlan.da=={ap_bssid})" -Tfields -e "wlan.fc.type_subtype" -e "frame.time" -e "frame.time_relative" > {filter_files}/{test_case}_uni_cast.txt'
    wifi_sniffer.interfaces.capture.shell(filter3)

    logger().info("Getting broad_cast probe_requests from the filtered file")
    filter4 = f'tshark -r {filtered_file} -Y "(wlan.fc.type_subtype eq 4 && wlan.da==ff:ff:ff:ff:ff:ff)" -Tfields -e "wlan.fc.type_subtype" -e "frame.time" -e "frame.time_relative" > {filter_files}/{test_case}_broadcast.txt'
    wifi_sniffer.interfaces.capture.shell(f"{filter4}; sudo chmod +777 {filter_files}/*")

    if isinstance(wifi_sniffer.interfaces.capture.shell, SSHShell):
        with wifi_sniffer.interfaces.capture.shell.client.open_sftp() as sftp_main:
            sftp_main.get(filtered_file, f"./reports/{test_case}_delta_filter.pcap")
            uni_cast_file = f"./reports/{test_case}_uni_cast.txt"
            broadcast_file = f"./reports/{test_case}_broadcast.txt"
            sftp_main.get(f"{filter_files}/{test_case}_uni_cast.txt", uni_cast_file)
            sftp_main.get(f"{filter_files}/{test_case}_broadcast.txt", broadcast_file)
            sftp_main.close()

    def get_time(file_name):
        first_probe_time = 0
        with open(file_name) as f:
            for line in f:
                if float(line.split()[-1]) >= float(last_beacon_time):
                    first_probe_time = float(line.split()[-1])
                    f.close()
                    break
        return first_probe_time

    unicast_probe_time = get_time(uni_cast_file)
    logger().info(f"first unicast_probe_time after last beacon is:{unicast_probe_time} seconds")
    assert unicast_probe_time, "No unicast probe request found from DUT even after AP is switched off"
    time_diff_unicast = int(round((unicast_probe_time - last_beacon_time), 2))
    logger().info(
        f"Time difference between last beacon and first unicast probe request time is: {time_diff_unicast} seconds")

    broadcast_probe_time = get_time(broadcast_file)
    logger().info(f"first broadcast_probe_time after last beacon is:{broadcast_probe_time} seconds")
    if broadcast_probe_time > 0:
        time_diff_broadcast = int(round((broadcast_probe_time - last_beacon_time), 2))
        logger().info(
            f"Time difference between last beacon and first broadcast probe request time is: {time_diff_broadcast} seconds")
    else:
        logger().info("No broadcast probe request found from DUT even after AP is switched off")


@retry(Exception, delay=15, tries=5)
def ping_to_dut(dut_ip, ping_count=10):
    status = ping(dut_ip, ping_count)
    assert status, "Failed to ping to DUT"
    return status


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
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_c19721',
                                                       test_case_id='c19721',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_c19721(switch, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):
    """Stop rejoin process by issuing Disconnect command and then do scan and join to the network If Module stops rejoin
         process and gives success message to host AND If Module join to network after disconnect then PASS else FAIL"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

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

        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_c19721')

        logger().info('***** Turn off Access point *****')
        switch.interfaces.pdu_switch.turn_off(delay=150)

        packet_filter3 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        wifi_dut.interfaces.wifi.leave()
        time.sleep(3)

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        # Repeat step 5-11
        logger().info("Joining to AP")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)
        time.sleep(5)
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
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_max_retry_failure_c19722',
                                                       test_case_id='c19722',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_max_retry_failure_c19722(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Do scan, Join after rejoin failure and validate Rejoin max retry"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True
        rejoin_value = 4

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_max_retry_failure_c19722')
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

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
            wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)

        time.sleep(2)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_broad_prob_req')
        time.sleep(5)
        logger().info("******* Turn off access point and waiting for Rejoin error*******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        """validate rejoin retry failure"""
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 1, "rejoin fail event not found even after AP is switched off for 350 seconds"

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        # Validating Probe req broadcast packet
        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['find_packet_num'])

        message = f"Broadcast probe request packet count '{packet_count}' is not equal to one less rejoin value {rejoin_value}"
        assert packet_count == (rejoin_value - 1), message
        logger().info(
            f"Successfully matched Broadcast probe request packet count:'{packet_count}' to one less than rejoin_max_value:'{rejoin_value}'")

        logger().info("****** Access point is going to turn on  ******")
        switch.interfaces.pdu_switch.turn_on(delay=60)

        logger().info("Joining to AP")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(2)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)

        if connect_status is False:
            logger().info(f"Unable to connect with Server {connect_status}")
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
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_scan_all_channels_c19723',
                                                       test_case_id='c19723',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_scan_all_channels_c19723(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Check rejoin is happening in All channels(1-11) or not and Verify whether module is sending probe requests in all
       channels or not"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True
        channel_list_2g = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        result_list = []

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_access_point.interfaces.wifi.start_ap()
        time.sleep(15)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_All_channels_c19723')

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")
        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()

        time.sleep(2)
        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(2)

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
        # wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=60)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(
            f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list_2g}\n\n")
        for channel in channel_list_2g:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(100)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()

            packet_filter1 = f'(wlan_radio.channel == {channel} ' \
                             f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and ' \
                             f'(wlan.sa == {mac_address})'

            output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count']
            result_list.append(bool(output))
            logger().info(f"result = {result_list}")
            if False in result_list:
                message = f'Unable to find Broadcast Probe request packet in channel = {channel}'
                logger().info(message)
                assert False, message
            time.sleep(5)
        del result_list

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_selected_channel_c19725',
                                                       test_case_id='c19725',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_selected_channel_c19725(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """select particular channels(ex: select 1,6,11) and Check rejoin is happening only in selected channels or not and
           Verify whether module is sending probe request only in selected channel"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True
        result_list = []

        channel_list = [1, 6, 8]
        channel_bitmap_2_4 = 0
        scan_expected_time = 0
        for count in channel_list:
            channel_bitmap_2_4 += 1 << (count - 1)
            scan_expected_time += 100

        channel_bitmap_5 = 0
        scan_feature_extend = 0

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_access_point.interfaces.wifi.start_ap()

        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=4, beacon_missedcount=40, first_time_retry=0)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_selected_channel_c19725')
        scan_results = wifi_dut.interfaces.wifi.scan_selective_channel(channel=0, ssid=None,
                                                                       scan_bitmap_2_4=channel_bitmap_2_4,
                                                                       scan_bitmap_5=channel_bitmap_5,
                                                                       scan_feature=scan_feature_extend)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        time.sleep(2)
        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(2)

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
        # wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=60)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        logger().info(f"\n\n Broadcast Probe request packet validation is start for channel = {channel_list}\n\n")
        for channel in channel_list:
            file_name = f'test_rejoin_for_ch_{channel}'
            wifi_sniffer.interfaces.capture.configure_interface(channel=channel)
            time.sleep(2)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info("Delaying for some time to get the capture")
            time.sleep(100)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(3)

            packet_filter1 = f'(wlan_radio.channel == {channel} ' \
                             f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and ' \
                             f'(wlan.sa == {mac_address})'

            output = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)[
                'packet_count']
            result_list.append(bool(output))
            logger().info(f"result = {result_list}")
            if False in result_list:
                message = f'Unable to find Broadcast Probe request packet in channel = {channel}'
                logger().info(message)
                assert False, message
            time.sleep(5)
        del result_list
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_max_retry_failure_with_security_mode_change_c19729',
                                                       test_case_id='c19729',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_max_retry_failure_with_security_mode_change_c19729(wifi_sniffer, wifi_access_point, wifi_dut, switch,
                                                                   utf_constants):
    """Verify rejoin functionality by changing connected AP security settings in 2.4Ghz"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True
        rejoin_value = 4

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(
            capture_file='test_rejoin_max_retry_failure_with_security_mode_change_c19729')
        time.sleep(3)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=6, beacon_missedcount=40,
                                        first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        time.sleep(2)
        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(2)

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
        # wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_max_retry_failure_c19729')
        time.sleep(3)

        logger().info("Changing the PSK of AP")
        wifi_access_point.interfaces.wifi.start_ap(security=SecurityMode.WPA2Enterprise)

        """validate rejoin retry failure"""
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 1, f"rejoin fail event not found even after AP is switched off for {end_time} seconds"

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'( wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff and (wlan.sa == {dut_mac_address}))'
        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['find_packet_num'])

        message = f"Broadcast probe request packet count '{packet_count}' is not equal to one less rejoin value {rejoin_value}"
        assert packet_count == (rejoin_value - 1), message
        logger().info(
            f"Successfully matched Broadcast probe request packet count:'{packet_count}' to one less than rejoin_max_value:'{rejoin_value}'")

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_disable_c19733',
                                                       test_case_id='c19733',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_disable_c19733(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Verify default number of retries in rejoin procedure, expecting 19 broadcast packet after Turn off
           Access point"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True
        rejoin_max_value = 20

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        logger().info(f"Configuring Rejoin parameters")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_max_value, scan_interval=6, beacon_missedcount=40,
                                        first_time_retry=0)
        time.sleep(3)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")
        time.sleep(2)

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

        # wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        wifi_dut.interfaces.wifi.associated = False
        wifi_sniffer.interfaces.capture.start_capture()

        logger().info("\n\n ****** Access point is going to turn off and waiting for Rejoin Error from DUT ******")
        switch.interfaces.pdu_switch.turn_off(delay=200)

        """validate rejoin retry failure"""
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 1, "rejoin fail event not found even after AP is switched off for 400 seconds"

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['find_packet_num'])

        message = f"Broadcast probe request packet count '{packet_count}' is not equal to one less rejoin value {rejoin_max_value}"
        assert packet_count == (rejoin_max_value - 1), message
        logger().info(
            f"Successfully matched Broadcast probe request packet count:'{packet_count}' to one less than rejoin_max_value:'{rejoin_max_value}'")
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_psk_change_c19734',
                                                       test_case_id='c19734',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_psk_change_c19734(switch, wifi_sniffer, wifi_access_point, wifi_dut, utf_constants):
    """Verify rejoin procedure when connected AP, PSK got changed"""
    try:
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        if wifi_dut.interfaces.wifi.associated is True:
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=4, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        wifi_join(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_psk_change_19734')
        time.sleep(5)

        logger().info('******* Changing the passphrase in Access point **********')
        wifi_access_point.interfaces.wifi.start_ap(passphrase="87654321")

        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 1, f"rejoin fail event not found even after AP is switched off for {end_time} seconds"

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        try:
            packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                             f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find Broadcast packet'
        except:
            logger().info("Unable to find Broadcast packet")
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)

pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_with_disconnect_c19735',
                                                       test_case_id='c19735',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_with_disconnect_c19735(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Issue Disconnect command when module does not find AP in rejoin procedure when first time retry enable bit and
           number of retries to infinite"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        time.sleep(2)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

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

        # wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_with_disconnect')
        time.sleep(3)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=120)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast packet'

        logger().info('************Disconnect the DUT from AP*******************')
        wifi_dut.interfaces.wifi.leave()
        wifi_dut.interfaces.wifi.associated = False
        wifi_dut.interfaces.wifi.inited = False
        logger().info("******** Turn on the access point ********")
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_dut.interfaces.wifi.init()
        logger().info("Joining into wifi_access_point")
        wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        time.sleep(3)
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_beacon_miss_counter_c19736',
                                                       test_case_id='c19736',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_beacon_miss_counter_c19736(wifi_sniffer, wifi_access_point, wifi_dut, switch):
    """ Verify beacon miss counter is resetting or not after AP finding in rejoin process """
    try:
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1000

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_beacon_miss_counter_19736_1')
        time.sleep(3)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=100, first_time_retry=0)
        time.sleep(2)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        dut_mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
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

        '''Post power off AP DUT will try for the rejoin process that we can check in sniffer(i.e: post power off AP need 
        to check in sniffer whether the DUT is sending broadcast probe requests or not'''

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=120)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        logger().info(
            "Validating time difference between last beacon received and first unicast and broadcast probe request from DUT")
        delta_btwn_last_beacon_and_first_probe_req(wifi_sniffer, dut_mac_address, ap_bssid,
                                                   test_case="test_19736_counter1")

        # Again checking the time difference between last beacon received and first unicast & broadcast probe request
        logger().info("Start sniffer capture again")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_beacon_miss_counter_19736_2')
        time.sleep(5)
        logger().info('******* Turn on Access point **********')
        logger().info(
            "\n\n****** Wait... for 120 seconds, AP radio turn on and broadcast probe request from DUT ******")
        switch.interfaces.pdu_switch.turn_on(delay=120)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=120)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        logger().info(
            "Again validating time difference between last beacon received and first unicast and broadcast probe request from DUT")
        delta_btwn_last_beacon_and_first_probe_req(wifi_sniffer, dut_mac_address, ap_bssid,
                                                   test_case="test_19736_counter2")

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_scan_interval_1sec_c19737',
                                                       test_case_id='c19737',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_scan_interval_1sec_c19737(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Set scan interval to 1 sec in rejoin params command Verify scan interval time in rejoin process"""
    try:
        end_time = utf_constants.get("time_duration")
        tcp_socket_obj = IopTcpIpSockets()
        scan_interval = 1
        send_bytes = 1000
        validation = True
        packet_filter2 = '    Type/Subtype: Probe Request (0x0004)'
        time_delta = 1
        status = False
        probe_time_delta_obj = FilterPacket()

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        if wifi_dut.interfaces.wifi.associated is True:
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=4, scan_interval=scan_interval, beacon_missedcount=40,
                                        first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

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

        # wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_scan_interval_1sec')

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off()

        """validate rejoin retry failure"""
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 1, f"rejoin fail event not found even after AP is switched off for {end_time} seconds"

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)
        wifi_dut.interfaces.wifi.associated = False

        packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {mac_address} ' \
                         f'and wlan.ssid == {wifi_access_point.interfaces.wifi.ssid} and wlan.fc.type_subtype == 0x0004 ' \
                         f'and wlan.da == ff:ff:ff:ff:ff:ff'
        result = wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1, packet_filter2)[
            'packet_count']
        probe_packets_time_delta_list = probe_time_delta_obj.delta_between_probe_packet()
        logger().info(f'Probe packet time delta list= {probe_packets_time_delta_list}')

        probe_packets_time_delta_list.pop(0)
        logger().info(f'Probe packet time delta list after removing 0 = {probe_packets_time_delta_list}')
        for time_diff in probe_packets_time_delta_list:
            logger().info(int(time_diff))
            is_between = int(time_diff) in range(time_delta, time_delta + 1)
            if is_between is False:
                logger().info(is_between)
                status = is_between
                break
            else:
                logger().info(is_between)
                status = is_between
        '''If time gap between 2 successful broadcast packets is ~1sec then PASS else FAIL'''
        if result and status is True:
            logger().info(f'Expected scan interval {scan_interval}sec found between Probe request packets')
            assert True
        else:
            logger().info(f'Expected scan interval {scan_interval}sec not found between Probe request packets')
            assert False

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_infinite_retry_c19738',
                                                       test_case_id='c19738',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tx_wait_time": 16000,
    }
)
def test_rejoin_infinite_retry_c19738(wifi_sniffer, wifi_access_point, wifi_dut, switch):
    """Verify rejoin functionality by setting number of retries to infinite"""
    try:
        tcp_socket_obj = IopTcpIpSockets()
        send_bytes = 1450
        validation = True
        rejoin_value = 0
        end_time_sec = 300

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40, first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
        logger().info(f"Setting the tcp retry count for the socket_id->{tcp_socket_id} to {SocketOptions.TCP_MAX_RETRY}"
                      f" seconds")
        wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)

        '''Verify first scenario, data transfer should resume once it is reconnected to the AP '''
        wifi_sniffer.interfaces.capture.start_capture(capture_file='rejoin_max_retry_validation')

        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time_sec:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes, timeout=60)
                logger().info(f'SEND-RESPONSE = {send_response}')
                if b"-1" in send_response:
                    try:
                        wifi_dut.interfaces.wifi.wlan_get_status()
                    except:
                        wifi_dut.interfaces.wifi.wlan_get_socket_info()
                        break
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes, timeout=60)
                    logger().info(f'SEND-RESPONSE = {send_response}')
                    if b"-1" in send_response:
                        try:
                            wifi_dut.interfaces.wifi.wlan_get_status()
                        except:
                            wifi_dut.interfaces.wifi.wlan_get_socket_info()
                            break
                    time.sleep(1)

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    switch.interfaces.pdu_switch.turn_off(delay=20)

                    logger().info('******* Turn on Access point **********')
                    switch.interfaces.pdu_switch.turn_on(delay=60)
                    check_flag = True
        time.sleep(5)

        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off()

        """validate rejoin retry failure"""
        logger().info("Checking for rejoin fail event from dut, this may take some time....")
        sw = Stopwatch()
        rejoin_msg = 0
        end_time = 200
        while sw.elapsed_sec <= end_time:
            events = wifi_dut.interfaces.wifi.get_async_events()
            if len(events):
                for event in events:
                    if event.event_type == RS9116AsyncEventType.RejoinError:
                        rejoin_msg = 1
                        logger().info(
                            "******** Rejoin error found from DUT, which is not expected as per the test step ********")
            if rejoin_msg:
                break
        assert rejoin_msg == 0, f"rejoin fail event found from DUT which is not expected as per test step"

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=30)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast probe request packet'

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_with_bgscan_c19739',
                                                       test_case_id='c19739',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_with_bgscan_c19739(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """ Re-join with infinite retry when bgscan enable"""
    try:
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        if wifi_dut.interfaces.wifi.associated is True:
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_with_bgscan')
        time.sleep(3)

        wifi_dut.interfaces.wifi.set_bgscan(1, 0, 10, 4, 10, 15, 20, 0)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        time.sleep(2)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        time.sleep(2)
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter3 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_first_time_retry_c19740',
                                                       test_case_id='c19740',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
def test_rejoin_first_time_retry_c19740(wifi_sniffer, wifi_access_point, wifi_dut, switch):
    """Verify first time retry functionality when AP sends de-auth frame while connecting"""
    try:
        validation = True
        rejoin_retry_value = 4

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        if wifi_dut.interfaces.wifi.associated is True:
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_retry_value, scan_interval=6, beacon_missedcount=200,
                                        first_time_retry=1)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_first_time_retry')
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point, passphrase="12345679", timeout=30)
            assert exc_info.value.error_code == 0x8 or 0x19
        time.sleep(30)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        # Try to validate M2 packets 4 times (becz rejoin_max=4), after first de-authentication packet.
        packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and radiotap.timestamp.ts >= ' \
                         f'12256739 and wlan_rsna_eapol.keydes.msgnr == 2'
        packet_count = int(
            wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter3)['find_packet_num'])

        message = f"Rejoin retry value:'{rejoin_retry_value}' is not equal to No of M2 packet count:'{packet_count}'"
        assert packet_count == rejoin_retry_value, message
        logger().info(
            f"Rejoin retry value:'{rejoin_retry_value}' is not equal to No of M2 packet count:'{packet_count}'")
        wifi_dut.interfaces.wifi.associated = False

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_hidden_ssid_c19741',
                                                       test_case_id='c19741',
                                                       notes='test notes'))
@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"ssid": 'Hidden_SSID_C19741', "broadcast_ssid": False})
def test_rejoin_hidden_ssid_c19741(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Rejoin functionality with hidden mode AP"""
    try:
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        if wifi_dut.interfaces.wifi.associated is True:
            wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        time.sleep(2)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_hidden_ssid')
        time.sleep(3)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Initiating wlan Scan from DUT")
        scan_results = wifi_dut.interfaces.wifi.scan(ssid=None)
        logger().info(scan_results)
        assert len(scan_results) > 0, "scan_list not found"

        logger().info("Joining into wifi_access_point")
        join_error = False
        with pytest.raises(WlanError) as exc_info:
            wifi_dut.interfaces.wifi.join_ap(wifi_access_point)
        logger().info(f"Join_Error: {exc_info.value}")
        if exc_info.value.error_code:
            join_error = True
            logger().info("Received Access Point not found Error...Hence passing the testcase as per the test step")

        if not join_error:
            ip_config = wifi_dut.interfaces.wifi.start_ip()
            assert isinstance(ip_config,
                              wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
            dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
            assert dut_ip, "ip setting in DUT has failed"
            logger().info(f'DUT ip {dut_ip}')

            logger().info("Initiating wlan power save on DUT")
            enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                 RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_wifi_ps, "Failed to enable wifi power save"

            logger().info("Initiating bt power save on DUT")
            enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                                  RS9116PowerSaveProcedureTypes.FastPowerSave)
            assert enable_bt_ps, "Failed to enable bt power save"
            logger().info("*****Enabled ENH Max PSP in DUT******")

            # Initiate ping from third party wifi-client to DUT
            status = ping_to_dut(dut_ip, ping_count)
            assert status, "Failed to ping to DUT"

            mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
            logger().info(f"DUT MAC_Address: {mac_address}")

            time.sleep(2)
            logger().info("\n\n ****** Access point is going to turn off  ******")
            switch.interfaces.pdu_switch.turn_off(delay=150)

            logger().info("Stop sniffer capture")
            wifi_sniffer.interfaces.capture.stop_capture()
            time.sleep(5)

            packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                             f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
            assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
                'Unable to find Broadcast Probe request packet'

            logger().info("Turn on Access Point")
            switch.interfaces.pdu_switch.turn_on(delay=100)

            # Initiate ping from third party wifi-client to DUT
            status = ping_to_dut(dut_ip, ping_count)
            assert status, "Failed to ping to DUT"

            if status:
                logger().info('**** DUT successfully re-associated after AP power turn on ****')
            else:
                logger().info('DUT failed to reconnect after AP power turn on ')
    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_in_us_region_c19742',
                                                       test_case_id='c19742',
                                                       notes='test notes'))
# NOT ANNOUNCED
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 1, "region_code": RS9116RegionCode.US, "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "US", "channel": 11})
def test_rejoin_in_us_region_c19742(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """ Verify Rejoin Functionality with US region enabled in 2.4GHZ band"""
    try:
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_US_region')
        time.sleep(3)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        time.sleep(2)
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_in_eu_region_c19743',
                                                       test_case_id='c19743',
                                                       notes='test notes'))
# NOT ANNOUNCED
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 1, "region_code": RS9116RegionCode.Europe, "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Europe", "channel": 12})
def test_rejoin_in_eu_region_c19743(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """Verify Rejoin Functionality with EU region enabled in 2.4GHZ band"""
    try:
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_UK_region')
        time.sleep(3)
        # Set the region value in AP side
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        time.sleep(2)
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'

        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_in_japan_region_C19744',
                                                       test_case_id='C19744',
                                                       notes='test notes'))
# NOT ANNOUNCED
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 1, "region_code": RS9116RegionCode.Japan, "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "US", "channel": 11})
def test_rejoin_in_japan_region_C19744(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """ Verify Rejoin Functionality with JP region enabled in 2.4GHZ band,
        # Please Note - ASUS AP doesn't have Japan region, So changed to US region"""
    try:
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_Japan_region')
        time.sleep(3)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        time.sleep(2)
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on ')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_in_worldwide_region_c19745',
                                                       test_case_id='c19745',
                                                       notes='test notes'))
# NOT ANNOUNCED
@pytest.mark.start_state("wifi_dut", wifi=['init'])
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable", "disassociated"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "region": 1, "region_code": RS9116RegionCode.Worldwide, "module_type": 1,
    }
)
@pytest.mark.config('wifi_access_point', wifi={"region": "Asia", "channel": 11})
def test_rejoin_in_worldwide_region_c19745(wifi_sniffer, wifi_access_point, wifi_dut, switch, utf_constants):
    """ Verify Rejoin Functionality with world mode region enabled in 2.4GHZ band"""
    try:
        end_time = utf_constants.get("time_duration")
        ping_count = utf_constants.get("ping_count")
        validation = True

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_in_worldwide_region')
        time.sleep(3)
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=0, scan_interval=6, beacon_missedcount=40, first_time_retry=0)
        time.sleep(2)

        logger().info("Joining into wifi_access_point")
        dut_ip = wifi_join(wifi_dut, wifi_access_point, ping_count)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        time.sleep(2)
        logger().info("\n\n ****** Access point is going to turn off  ******")
        switch.interfaces.pdu_switch.turn_off(delay=150)

        logger().info("Stop sniffer capture")
        wifi_sniffer.interfaces.capture.stop_capture()
        time.sleep(5)

        packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
                         f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == {mac_address})'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(validation, packet_filter1)['packet_count'], \
            'Unable to find Broadcast Probe request packet'

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=100)

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        if status:
            logger().info('**** DUT successfully re-associated after AP power turn on ****')
        else:
            logger().info('DUT failed to reconnect after AP power turn on')

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_eap_tls_c19730',
                                                       test_case_id='c19730',
                                                       notes='test notes'))
# EAP Connection in TLS mode
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tx_wait_time": 16000,
        "band": 0,
        "eap_cert": "wifi-user.pem"
    },
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.radius_server("static_radius_server")
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_rejoin_eap_tls_c19730(switch, wifi_sniffer, wifi_access_point, wifi_dut, radius_server, utf_constants):
    """Verify rejoin functionality in EAP-TLS mode"""
    try:
        ping_count = utf_constants.get("ping_count")
        tcp_socket_obj = IopTcpIpSockets()
        ap_user_name = "\\\"user1\\\""
        ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
        dut_ssid = wifi_access_point.interfaces.wifi.ssid
        dut_security = wifi_access_point.interfaces.wifi.security
        send_bytes = 1450
        end_time = 300
        rejoin_value = 0

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_c19730')

        logger().info("scanning for AP")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
        logger().info(scan_results)

        logger().info("Setting Rejoin Parameters in DUT")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info("DUT Joining to AP in EAP-TLS mode")
        wifi_dut.interfaces.wifi.eap_method(eap_method="TLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"",
                                            private_key="\"\"")
        wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)

        dut_ip = None
        for count in range(3):
            try:
                ip_config = wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
                time.sleep(10)
        assert dut_ip, "ip setting in DUT has failed"
        logger().info(f'DUT ip {dut_ip}')

        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"
        logger().info("*****Enabled ENH Max PSP in DUT******")

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
        logger().info(f"Setting the tcp retry count for the socket_id->{tcp_socket_id} to {SocketOptions.TCP_MAX_RETRY}"
                      f" seconds")
        wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status

        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                    logger().info(f'SEND-RESPONSE = {send_response}')

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    switch.interfaces.pdu_switch.turn_off(delay=20)

                    logger().info('******* Turn on Access point **********')
                    switch.interfaces.pdu_switch.turn_on(delay=60)
                    check_flag = True

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)
        wifi_sniffer.interfaces.capture.stop_capture()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_eap_ttls_c19731',
                                                       test_case_id='c19731',
                                                       notes='test notes'))
# EAP Connection in TTLS mode
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake
                    | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid
                           | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower
                               | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0
                           | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tx_wait_time": 16000,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
@pytest.mark.radius_server("static_radius_server")
def test_rejoin_eap_ttls_c19731(switch, wifi_sniffer, wifi_access_point, wifi_dut, radius_server, utf_constants):
    """Verify rejoin functionality in EAP-TTLS mode"""
    try:
        ping_count = utf_constants.get("ping_count")
        tcp_socket_obj = IopTcpIpSockets()
        ap_user_name = "\\\"user1\\\""
        ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
        dut_ssid = wifi_access_point.interfaces.wifi.ssid
        dut_security = wifi_access_point.interfaces.wifi.security
        send_bytes = 1450
        end_time = 300
        rejoin_value = 0

        logger().info('******* Turn on Access point **********')
        switch.interfaces.pdu_switch.turn_on(delay=60)

        wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_c19731')

        logger().info("Scanning for AP")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
        logger().info(scan_results)
        logger().info("Setting Rejoin parameters in DUT")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)
        logger().info("DUT Joining to AP in EAP-TTLS mode")
        wifi_dut.interfaces.wifi.eap_method(eap_method="TTLS", eap_inner_method="\\\"auth=MSCHAPV2\\\"",
                                            private_key="\"\"")
        wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        dut_ip = None
        for count in range(3):
            try:
                ip_config = wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
                time.sleep(10)
        assert dut_ip, "ip setting in DUT has failed"
        logger().info(f'DUT ip {dut_ip}')

        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"
        logger().info("*****Enabled ENH Max PSP in DUT******")

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
        logger().info(f"Setting the tcp retry count for the socket_id->{tcp_socket_id} to {SocketOptions.TCP_MAX_RETRY}"
                      f" seconds")
        wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)

        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        if connect_status is False:
            logger().info("Unable to connect with Server")

            assert connect_status
        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                    logger().info(f'SEND-RESPONSE = {send_response}')

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    switch.interfaces.pdu_switch.turn_off(delay=20)

                    logger().info('******* Turn on Access point **********')
                    switch.interfaces.pdu_switch.turn_on(delay=60)
                    check_flag = True

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)
        wifi_sniffer.interfaces.capture.stop_capture()


pytestmark = [
    pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='FEATURE',
                                                          feature_name='smoke_tests',
                                                          test_creation_date='2022-06-06',
                                                          module_name='wifi',
                                                          test_description='module desc',
                                                          iot_req_id='IOTREQ-1194',
                                                          tool_chain='tool_chain',
                                                          test_case_version_num=1,
                                                          test_suite_name='test_suite_name',
                                                          phy_name='phy_name',
                                                          vendor_result='vendor_result',
                                                          vendor_build='vendor_build',
                                                          vendor_name='vendor_name',
                                                          portal_watch='true',
                                                          test_parametric_data='p1'
                                                          ))
]
@pytest.mark.database_properties(UtfDatabaseProperties(test_result_type='SQA_Regression',
                                                       test_case_name='test_rejoin_eap_peap_c19732',
                                                       test_case_id='c19732',
                                                       notes='test notes'))
# EAP Connection in PEAP mode
@pytest.mark.config(
    "wifi_dut",
    wifi=
    {
        "oper_mode": 2,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.OpenMode | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.Aggregation,
        "tcpip_features": RS9116TCPIPFeatureBitMap.DHCPv4Client | RS9116TCPIPFeatureBitMap.ExtTCPIPFeatureBitmapValid,
        "custom_features": RS9116CustomFeatureBitMap.ExtCustomFeatureBitmapValid | RS9116CustomFeatureBitMap.AsyncStatusMessagesToHost,
        "ext_custom_features": RS9116ExtCustomFeatureBitMap.FeatureLowPower | RS9116ExtCustomFeatureBitMap.Feature32KHzBypassClockOnUULP_GPIO_3
                               | RS9116ExtCustomFeatureBitMap.Feature384kBMemoryMode,
        "ext_tcpip_features": RS9116ExtTCPIPFeatureBitMap.WaitForSocketClose | RS9116ExtTCPIPFeatureBitMap.ConfigFeatureBitmapValid
                              | RS9116CertificateType.EAPClientCertificate,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
        "tx_wait_time": 16000,
        "band": 0,
    }
)
@pytest.mark.start_state("wifi_dut", device='reset', wifi="init")
@pytest.mark.radius_server("static_radius_server")
@pytest.mark.config('wifi_access_point',
                    wifi={"security": 'WPA2Enterprise', "passphrase": '12345678'})
@pytest.mark.end_state("wifi_dut", wifi=["disassociated", "clear_certs"])
def test_rejoin_eap_peap_c19732(switch, wifi_sniffer, wifi_access_point, wifi_dut, radius_server, utf_constants):
    """Verify rejoin functionality in EAP-, PEAP mode"""
    try:
        ping_count = utf_constants.get("ping_count")
        tcp_socket_obj = IopTcpIpSockets()
        ap_user_name = "\\\"user1\\\""
        ap_password = f"\\\"{wifi_access_point.interfaces.wifi.passphrase}\\\""
        dut_ssid = wifi_access_point.interfaces.wifi.ssid
        dut_security = wifi_access_point.interfaces.wifi.security
        send_bytes = 1450
        end_time = 300
        rejoin_value = 0

        wifi_dut.interfaces.wifi.clear_certificate(cert_type=1, cert_index=0)
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        logger().info("Start sniffer capture")
        wifi_sniffer.interfaces.capture.start_capture(capture_file='test_rejoin_c19732')

        logger().info("scanning for AP")
        scan_results = wifi_dut.interfaces.wifi.scan(channel=0, ssid=dut_ssid)
        logger().info(scan_results)

        logger().info("Setting Rejoin parameters in DUT")
        wifi_dut.interfaces.wifi.rejoin(rejoin_max=rejoin_value, scan_interval=4, beacon_missedcount=40,
                                        first_time_retry=0)

        logger().info("DUT Joining to AP in EAP-PEAP mode")
        wifi_dut.interfaces.wifi.eap_method(eap_method="PEAP", eap_inner_method="\\\"auth=MSCHAPV2\\\"",
                                            private_key="\"\"")
        wifi_dut.interfaces.wifi.eap_connect(dut_ssid, dut_security, ap_user_name, ap_password)

        mac_address = wifi_dut.interfaces.wifi.get_dut_mac_address()
        logger().info(f"DUT MAC_Address: {mac_address}")

        dut_ip = None
        for count in range(3):
            try:
                ip_config = wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                dut_ip = wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count + 1}")
                time.sleep(10)
        assert dut_ip, "ip setting in DUT has failed"
        logger().info(f'DUT ip {dut_ip}')

        logger().info("Initiating wlan power save on DUT")
        enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                             RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_wifi_ps, "Failed to enable wifi power save"

        logger().info("Initiating bt power save on DUT")
        enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
                                                              RS9116PowerSaveProcedureTypes.FastPowerSave)
        assert enable_bt_ps, "Failed to enable bt power save"
        logger().info("*****Enabled ENH Max PSP in DUT******")

        # Initiate ping from third party wifi-client to DUT
        status = ping_to_dut(dut_ip, ping_count)
        assert status, "Failed to ping to DUT"

        tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        time.sleep(5)
        logger().info(f"Setting the tcp retry count for the socket_id->{tcp_socket_id} to {SocketOptions.TCP_MAX_RETRY}"
                      f" seconds")
        wifi_dut.interfaces.wifi.set_socket_option(tcp_socket_id, SocketOptions.SOL_SOCKET, SocketOptions.TCP_RETRY,
                                                   SocketOptions.TCP_MAX_RETRY)
        connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        if connect_status is False:
            logger().info("Unable to connect with Server")
            assert connect_status
        else:
            sw = Stopwatch()
            check_flag = False
            while sw.elapsed_sec < end_time:
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'SEND-RESPONSE = {send_response}')
                time.sleep(1)
                while sw.elapsed_sec < 30:
                    send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                    logger().info(f'SEND-RESPONSE = {send_response}')

                if check_flag is not True:
                    logger().info('***** Turn off Access point *****')
                    switch.interfaces.pdu_switch.turn_off(delay=20)

                    logger().info('******* Turn on Access point **********')
                    switch.interfaces.pdu_switch.turn_on(delay=60)
                    check_flag = True

    except Exception as e:
        recovery_error_codes = ['0xffffffe2', '0xffffffd5']
        for error_code in recovery_error_codes:
            if error_code in str(e):
                logger().info('******* Initiating DUT Recovery using Reset **********')
                wifi_dut.interfaces.wifi.reset()
        raise e
    finally:
        clean_up_method(wifi_dut, switch)
        wifi_sniffer.interfaces.capture.stop_capture()