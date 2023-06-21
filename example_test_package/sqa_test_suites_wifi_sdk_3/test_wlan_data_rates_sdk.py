import re
import time
from retry import retry
import pytest as pytest
from utf.utils.iperf.iperf_utils import ping
from utf import UtfDatabaseProperties
from utf_wiseconnect.interfaces.cli.rs_sapi_commands import RSSAPICommands
from utf.utils.logger import get_logger
from utf_wiseconnect.devices.rs911x import RS9116CoexMode, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, \
    RS9116AsyncEventType, \
    RS9116CustomFeatureBitMap, RS9116PowerSaveModes, RS9116DataRate, RS9116RejoinParams, RS9116ExtCustomFeatureBitMap, \
    RS9116BTFeatureBitMap
from utf_wiseconnect.devices.rs911x import (
    RS9116TCPIPFeatureBitMap,
    RS9116ExtTCPIPFeatureBitMap, RS9116FeatureBitMap, RS9116ConfigFeatureBitMap, RS9116CustomFeatureBitMap,
    RS9116PowerSaveProcedureTypes,
)
from utf.utils.stopwatch import Stopwatch
from utf_wiseconnect_3.tests.interfaces.sl_wifi_test_agent_cli import SLWifiCLI
from utf_wiseconnect_3.tests.sl_status import SLStatus


def logger():
    return get_logger(__name__)


"""This function runs below test steps for DUT-RS9116
        1. Configuration of DUT in 2G : BGN
        2. Association of Third party AP's
        3. Get the valid IP address
        4. Create a new TCP/IP socket
        5. Bind the socket with DUT ip address
        6. Connect the client with server socket as specified port number.
        7. Validate all management packets in 1 Mbps data rates.
        8. Configure data rates at on 11/12/54 Mbps and check the data rate in sniffer.
        9. Verification of EAPOL packets for 1 Mbps data rates
        10. Verification of Basic data rates for Association req & Probe response

    setup requirement:
        1. DUT(RS9116)
        2. EFR32
        3. Raspberry PI4
        4. Access Point(Third Party AP's)
        5. Sniffer(NUC device)

    Author: Vivek Verma
"""


class SocketDataTransfer:
    def __init__(self, wifi_dut=None, dut_ip=None, time_period=None, data=None, data_transfer=True, switch=None,
                 wifi_access_point=None):
        self.wifi_dut = wifi_dut
        self.dut_ip = dut_ip
        self.time_period = time_period
        self.data = data
        self.data_transfer = data_transfer
        self.switch = switch
        self.socket_id = None
        self.wifi_access_point = wifi_access_point

    def socket_data_transfer(self):
        if isinstance(self.wifi_dut.interfaces.wifi, SLWifiCLI):
            self.socket_id = self.wifi_dut.interfaces.wifi.socket(timeout=15)
            if isinstance(self.socket_id, int):
                logger().info(f"Socket open successfully : {self.socket_id}")
            else:
                logger().error(f"Unable to open socket id: {self.socket_id}")
                raise RuntimeError(self.socket_id)

            logger().error(f"\n\n Socket bind in DUT for socket-id: {self.socket_id}")
            self.wifi_dut.interfaces.wifi.bind(socket_fd=self.socket_id, device_ip=self.dut_ip, timeout=15)
            logger().error(f"\n\n Trying to connect with server ")
            self.wifi_dut.interfaces.wifi.bsdSocketConnect(socket_fd=self.socket_id)

            if self.data_transfer:
                sw = Stopwatch()
                while sw.elapsed_sec < self.time_period:
                    send_bytes = self.wifi_dut.interfaces.wifi.bsdSocketSend(socket_fd=self.socket_id, data=self.data)
                    if isinstance(send_bytes, str):
                        logger().info(f"Send {send_bytes} bytes successfully")
                    else:
                        logger().info(f"Data transfer failed")

            self.wifi_dut.interfaces.wifi.bsdSockClose(socket_fd=self.socket_id)

    def clean_up_method(self):
        logger().info("\n\n ----------------------------Cleaning UP the DUT ----------------------------")
        try:
            logger().info('******* Turn on Access point Finally **********')
            logger().info("Disconnect from AP")
            self.wifi_dut.interfaces.wifi.leave()
            self.wifi_dut.interfaces.wifi.associated = False

        except:
            logger().info("******* Recovering the DUT  **********")
            # self.wifi_dut.interfaces.wifi.reset()
        logger().info("\n ----------------------------Cleaning UP of DUT is Completed ----------------------------")

    def verify_data_rates(self):
        packet_filter = '    Data rate:'
        data_rates_list = []

        filter_file = open(f'./reports/filter2_file.txt', 'r')
        line = filter_file.readlines()
        for find_filter in line:
            if packet_filter in find_filter:
                data_rates = find_filter.split(':')[1].strip().split(' ')[0].split('.')[0]
                data_rates_list.append(data_rates)

        filter_file.close()
        return max(set(data_rates_list), key=data_rates_list.count)

    @retry(Exception, delay=15, tries=5)
    def ping_to_dut(self, ping_count=10):
        status = ping(self.dut_ip, ping_count)
        assert status, "Failed to ping to DUT"
        return status

    def wifi_join(self, ping_count=10):
        logger().info(f"Initiating wlan join from DUT")
        for i in range(3):
            try:
                # wifi_dut.interfaces.wifi.associated = False
                self.wifi_dut.interfaces.wifi.scan(ssid=None, channel=self.wifi_access_point.interfaces.wifi.channel)
                time.sleep(3)
                self.wifi_dut.interfaces.wifi.join_ap(self.wifi_access_point)
                time.sleep(5)
                break
            except Exception as e:
                logger().info(f"Error found:{str(e)} ----> Count{i} ")
                if "0x2" in str(e):
                    logger().info(
                        f"Error found:{str(e)} ----> Device already in connected step need to disconnect before connect")
                    logger().info("Initiating disconnect for cleanup")
                    self.wifi_dut.interfaces.wifi.leave(skip_check_for_association=True)
                    self.wifi_dut.interfaces.wifi.associated = False
                    time.sleep(5)
                if i == 2:
                    raise e

        self.dut_ip = None
        for count in range(1, 4):
            try:
                ip_config = self.wifi_dut.interfaces.wifi.start_ip()
                assert isinstance(ip_config,
                                  self.wifi_dut.interfaces.wifi.IPConfig), f"Failed to get IP address. Result = {ip_config}"
                self.dut_ip = self.wifi_dut.interfaces.wifi.ip.ip.decode('utf-8')
                break
            except:
                logger().info(f"Get IP address through dhcp process is failed. retry count -> {count}")
                time.sleep(10)
        assert self.dut_ip, "ip setting in DUT has failed"
        logger().info(f'\n\n *** DUT ip {self.dut_ip}\n\n ***')

        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"
        # logger().info("*****Enabled ENH Max PSP in DUT******")

        status = False
        for count in range(5):
            try:
                logger().info("pinging to dut after power-save.....")
                status = self.ping_to_dut(ping_count)
                logger().info("ping to DUT is successful....")
                break
            except:
                logger().info(f"ping to dut is failed...retry count->{count + 1}")
                time.sleep(15)
        assert status, "DUT not responding for ping request......"
        return self.dut_ip


@pytest.mark.start_state("wifi_dut", wifi="init")
# @pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_mgmt_data_rates_c19622(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Data rates used for Management packets, Verify for following management packets,Assoc req,Assoc resp.Reassoc 
    req,Re assoc resp,Probe req,Prob res'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        socket_obj.wifi_join(ping_count=ping_count)

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT dut_mac_address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        # Verification of Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth mgmt packets
        # datarates
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0004 or wlan.fc.type_subtype == 0x000b or wlan.fc.type_subtype == ' \
        #                  f'0x0000 ' \
        #                  f'or wlan.fc.type_subtype == 0x000c and wlan_radio.data_rate == 1 and !(wlan.fc.type_subtype == ' \
        #                  f'0x000d) and !(wlan.fc.type_subtype == 0x0020) '

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_1_mbps')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(2)
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth mgmt packets'

    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()



# @pytest.mark.start_state("wifi_dut", wifi="init")
# @pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
# @pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
# @pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
# @pytest.mark.config(
#     "wifi_dut",
#     wifi={
#
#         "oper_mode": 0,
#         "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
#         "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
#         "custom_features": RS9116CustomFeatureBitMap.Default,
#         "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
#     },
# )
def test_wifi_sdk_mgmt_data_rates_rts_cts_c19623(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Data rates used for Control packets, Verify for following Control packets,Block ACK Req,(Qos)Block Ack(Qos)
       Ps-PollRTSCTSACK'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

    
        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT ip address : {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_mac_address}')

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        """Verification of Block ack req/res, RTS/CTS mgmt packets data rates"""
        # Block Ack req & RTS
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0018 or wlan.fc.type_subtype == 0x001b and wlan_radio.data_rate == 1'
        # # Block Ack req & CTS
        # packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {ap_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0019 or wlan.fc.type_subtype == 0x001c and wlan_radio.data_rate == 1'

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_block_ack_req_rts_1mbps')
        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_block_ack_res_cts_1mbps')
        logger().info(f"\n\n\n Sniffer Filter = {packet_filter1}\n\n")

        logger().info(f"\n\n\n Sniffer Filter = {packet_filter2}\n\n")

        # tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        # connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        # if connect_status is False:
        #     logger().info("Unable to connect with Server")
        #     assert connect_status
        # else:
        #     send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        #     logger().info(f'SEND-RESPONSE = {send_response}')
        #     if 'status 10' in str(send_response):
        #         result = send_response.decode().replace("\r\n", '').strip()
        #         match = re.findall(r"\d+", result)
        #         if int(match[1]) == send_bytes:
        #             logger().info(f"Send {send_bytes} bytes successfully")
        #     else:
        #         logger().info(f"Data transfer failed")
        #         assert send_response
        #     time.sleep(2)
        #     wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)

        # socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        time.sleep(1)
        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)
        if result1 is False or result2 is False:
            logger().info(
                f"Expected packet validation failed, Block Ack req/RTS = {result1}, Block Ack res/CTS = {result2}")
            assert False
        else:
            logger().info(
                f"Block Ack req/RTS = {result1}, Block Ack res/CTS = {result2}")
            logger().info("Sniffer validation Passed")
            assert True
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_for_data_packet_c19624(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''	Data rates used for Data packets, Verify for following Data packets,Data.Null Data and Qos Null data.Qos Data '''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT ip address : {dut_ip}")
    
        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")
    
        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        # 
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"
    
        """Verification of Data/Null/Qos packets data rates"""
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0028 or wlan.fc.type_subtype == 0x0020 or ' \
        #                  f'wlan.fc.type_subtype == 0x0024 and !(wlan_radio.data_rate == 1) and !wlan.mgt'

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_data_null_Qos_1mbps')
        
    
        # tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        # connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        # if connect_status is False:
        #     logger().info("Unable to connect with Server")
        #     assert connect_status
        # else:
        #     send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        #     logger().info(f'SEND-RESPONSE = {send_response}')
        #     if 'status 10' in str(send_response):
        #         result = send_response.decode().replace("\r\n", '').strip()
        #         match = re.findall(r"\d+", result)
        #         if int(match[1]) == send_bytes:
        #             logger().info(f"Send {send_bytes} bytes successfully")
        #     else:
        #         logger().info(f"Data transfer failed")
        #         assert send_response
        #     wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        
        # socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find Data/Null/Qos packets data rates'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_for_b_mode_c19625(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Set data rate to 11b rates, and verify all following packets with all data rates Assoc Req,Assoc Resp.ReAssoc 
    Req,Re Assoc Resp.Probe Req,Probe RespBeacon.DisAssoc.'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        ap_mac_address = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_mac_address}')

        """set data rate in b(11Mbps) mode and Verify """
        wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11b", data_rate="11Mbps",
                                                   expected_status=SLStatus.SL_STATUS_OK)

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT ip address : {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        # Validating Data/Qos/Null packet for 11 Mbps data rates
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {ap_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0028 or wlan.fc.type_subtype == 0x0020 or ' \
        #                  f'wlan.fc.type_subtype == 0x0024 and wlan_radio.data_rate == 11 and !wlan.mgt '
        #
        # # Validating Assoc Req, Assoc Resp, ReAssoc Req, ReAssoc Resp. Probe Req,Probe Resp for 1 Mbps data rates
        # packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {ap_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0004 or wlan.fc.type_subtype == 0x000b or wlan.fc.type_subtype == ' \
        #                  f'0x0000 ' \
        #                  f'or wlan.fc.type_subtype == 0x000c and wlan_radio.data_rate == 1 and !(wlan.fc.type_subtype == ' \
        #                  f'0x000d) and !(wlan.fc.type_subtype == 0x0020)'

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_data_null_Qos_11mbps')

        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_assoc_reassoc_probe_req_res_1mbps')

        # tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        # connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        # if connect_status is False:
        #     logger().info("Unable to connect with Server")
        #     assert connect_status
        # else:
        #     send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        #     logger().info(f'SEND-RESPONSE = {send_response}')
        #     if 'status 10' in str(send_response):
        #         result = send_response.decode().replace("\r\n", '').strip()
        #         match = re.findall(r"\d+", result)
        #         if int(match[1]) == send_bytes:
        #             logger().info(f"Send {send_bytes} bytes successfully")
        #     else:
        #         logger().info(f"Data transfer failed")
        #         assert send_response
        #     time.sleep(2)
        #     wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)

        # socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find any packets for Data/Qos/Null packet for 11 Mbps dat rates'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find packets for Assoc Req, Assoc Resp, ReAssoc Req, ReAssoc Resp. Probe Req,Probe Resp for 1 Mbps ' \
            'data rates'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_for_g_mode_c19626(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Set data rate to 11g rates, and verify all following packets with all data ratesAssoc Req,Assoc Resp.ReAssoc 
       Req,Re Assoc RespProbe Req,Probe Resp'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        """set data rate in g mode(54 Mbps) and Verify """
        wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11g", data_rate="54Mbps",
                                                   expected_status=SLStatus.SL_STATUS_OK)

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT IP_Address: {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        # Validating Data/Qos/Null packet for 54 Mbps data rates
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0028 or wlan.fc.type_subtype == 0x0020 or wlan.fc.type_subtype == ' \
        #                  f'0x0024 and wlan_radio.data_rate == 54 and !wlan.mgt'
        #
        # # Validating Assoc Req, Assoc Resp, ReAssoc Req, ReAssoc Resp. Probe Req,Probe Resp for 1 Mbps data rates
        # packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0004 or wlan.fc.type_subtype == 0x000b or wlan.fc.type_subtype == ' \
        #                  f'0x0000 ' \
        #                  f'or wlan.fc.type_subtype == 0x000c and wlan_radio.data_rate == 1 and !(wlan.fc.type_subtype == ' \
        #                  f'0x000d) and !(wlan.fc.type_subtype == 0x0020) '

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_data_null_Qos_54mbps')

        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_assoc_reassoc_probe_req_res_1mbps')

        # socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find any packets for Data/Qos/Null packet for 54 Mbps dat rates'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find packets for Assoc Req, Assoc Resp, ReAssoc Req, ReAssoc Resp. Probe Req,Probe Resp for 1 Mbps ' \
            'data rates'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.config('wifi_access_point', wifi={"standard": '11n'})
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_for_n_mode_c19627(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Set data rate to 11n rates,and verify all following packets with all data ratesAssoc Req,Assoc RespReAssoc 
       Req,Re Assoc RespProbe Req,Probe RespBeaconDisAssoc'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # set data rate in n mode
        wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate="65Mbps",
                                                   expected_status=SLStatus.SL_STATUS_OK)

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT IP_Address: {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        # Verify Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth frame
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0004 or wlan.fc.type_subtype == 0x000b or wlan.fc.type_subtype == ' \
        #                  f'0x0000 ' \
        #                  f'or wlan.fc.type_subtype == 0x000c and wlan_radio.data_rate == 1 and wlan.tag.number == 45 and' \
        #                  f' !(wlan.fc.type_subtype == ' \
        #                  f'0x000d) and !(wlan.fc.type_subtype == 0x0020)'
        #
        # packet_filter2 = f'wlan.sa == {mac_address} and radiotap.mcs.index == 4'

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_probe_auth_Assoc_req_eapol_deauth_1mbps')

        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            filter_name='radio_mcs_index_4')

        socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Probe Request & Authentication Req & Association Req & EAPOL(2&4) and Deauth frame'
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
            'Unable to find the MCS rate 4 in data packets'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_for_data_packets_12mbps_C19628(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Set Fixed data rate to 12Mbps and verify which data rate is using for 4GHz .DataNull Data and Qos Null dataQos 
       Data'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        # set data rate in 12 Mbps
        wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate="12Mbps",
                                                   expected_status=SLStatus.SL_STATUS_OK)
        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT IP_Address: {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"
        # Verify Data/Null/Qos packets
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} or ' \
        #                  f'wlan.fc.type_subtype == 0x0028 or wlan.fc.type_subtype == 0x0020 or wlan.fc.type_subtype == ' \
        #                  f'0x0024 ' \
        #                  f'and wlan_radio.data_rate == 12 and !wlan.mgt'

        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_data_null_Qos_12mbps')

        # tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        # connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        # if connect_status is False:
        #     logger().info("Unable to connect with Server")
        #     assert connect_status
        # else:
        #     send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        #     logger().info(f'SEND-RESPONSE = {send_response}')
        #     if 'status 10' in str(send_response):
        #         result = send_response.decode().replace("\r\n", '').strip()
        #         match = re.findall(r"\d+", result)
        #         if int(match[1]) == send_bytes:
        #             logger().info(f"Send {send_bytes} bytes successfully")
        #     else:
        #         logger().info(f"Data transfer failed")
        #         assert send_response
        #     time.sleep(2)
        #     wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find any packet for Data/Null/Qos packets'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_for_rts_cts_12mbps_C19629(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    """Verification of Block ack req/res, RTS/CTS mgmt packets data rates for 12 Mbps"""
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Set Fixed data rate to 12Mbps and verify which data rate is using for 2.4GHz .Block ACK Req,(Qos)Block Ack(Qos)
       Ps-Poll, RTS, CTS, ACK'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(5)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate="12Mbps",
                                                            expected_status=SLStatus.SL_STATUS_OK)

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT IP_Address: {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        # Validating Block ACK Req, RTS for data rates 12 Mbps
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {mac_address} ' \
        #                  f'or wlan.fc.type_subtype == 0x0018 or wlan.fc.type_subtype == 0x001b and wlan_radio.data_rate ' \
        #                  f'== 12'
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_block_ack_req_rts_12mbps')

        socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find packets for Block ACK Req, RTS for data rates 12 Mbps'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()


@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={

        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_data_rates_eapol_C19631(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Data rates used for EAPOL key exchanges and GTK key renewal exchanges with auto rate'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)

        wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="802.11n", data_rate="12Mbps",
                                                            expected_status=SLStatus.SL_STATUS_OK)

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT IP_Address: {dut_ip}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"

        """Verification of EAPOL packets for 1 Mbps data rates"""
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan_rsna_eapol.keydes.key' \
        #                  f'_info.key_type == 1 and wlan_radio.data_rate == 1'
        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_data_rates_eapol_1mbps')

        # tcp_socket_id = tcp_socket_obj.open_socket(wifi_dut, dut_ip)
        # connect_status = tcp_socket_obj.connect_socket(wifi_dut, tcp_socket_id)
        # if connect_status is False:
        #     logger().info("Unable to connect with Server")
        #     assert connect_status
        # else:
        #     send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
        #     logger().info(f'SEND-RESPONSE = {send_response}')
        #     if 'status 10' in str(send_response):
        #         result = send_response.decode().replace("\r\n", '').strip()
        #         match = re.findall(r"\d+", result)
        #         if int(match[1]) == send_bytes:
        #             logger().info(f"Send {send_bytes} bytes successfully")
        #     else:
        #         logger().info(f"Data transfer failed")
        #         assert send_response
        #     time.sleep(2)
        #     wifi_dut.interfaces.wifi.close_socket(tcp_socket_id)
        socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()
        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
            'Unable to find packets for EAPOL packets for 1 Mbps data rates'
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()

@pytest.mark.start_state("wifi_dut", wifi="init")
@pytest.mark.start_state("wifi_sniffer", wifi="ap_enabled")
@pytest.mark.start_state("wifi_access_point", wifi="ap_enabled")
@pytest.mark.end_state("wifi_dut", wifi=["wifi_powersave_disable", "bt_powersave_disable"])
@pytest.mark.config(
    "wifi_dut",
    wifi={
        "oper_mode": 0,
        "coex_mode": RS9116CoexMode.WLAN | RS9116CoexMode.DualBluetoothBLE,
        "features": RS9116FeatureBitMap.Aggregation | RS9116FeatureBitMap.ULPGPIOHandshake | RS9116FeatureBitMap.PSKSecurity,
        "custom_features": RS9116CustomFeatureBitMap.Default,
        "config_features": RS9116ConfigFeatureBitMap.WakeupIndicationUULPGPIO0 | RS9116ConfigFeatureBitMap.EnahanceMaxPsp,
    },
)
def test_wifi_sdk_basic_data_rates_C19634(wifi_sniffer, wifi_access_point, wifi_dut, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    '''Verify data rates in Assoc Req, is same as data rates present in probe Resp of connected AP or not'''
    try:
        wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
        wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
        time.sleep(5)

        ap_bssid = wifi_access_point.interfaces.wifi.bssid
        logger().info(f'AP BSSID = {ap_bssid}')

        dut_ip = socket_obj.wifi_join(ping_count=ping_count)
        logger().info(f"DUT IP_Address: {dut_ip}")

        dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
        logger().info(f"DUT MAC_Address: {dut_mac_address}")

        # logger().info(f"*****Enable Max PSP in DUT******")
        # logger().info("Initiating wlan power save on DUT")
        # enable_wifi_ps = wifi_dut.interfaces.wifi.power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                      RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_wifi_ps, "Failed to enable wifi power save"
        #
        # logger().info("Initiating bt power save on DUT")
        # enable_bt_ps = wifi_dut.interfaces.wifi.bt_power_save(RS9116PowerSaveModes.PowerSaveMode2,
        #                                                       RS9116PowerSaveProcedureTypes.FastPowerSave)
        # assert enable_bt_ps, "Failed to enable bt power save"
        """Verification of Basic data rates for Association req & Probe response"""
        # Assoc req & Basic data rates
        # packet_filter1 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'and wlan.fc.type_subtype == 0x0000 or ((((wlan.supported_rates == 0x82) && ' \
        #                  f'(wlan.supported_rates == 0x84)) && (wlan.supported_rates == 0x8c)) && ' \
        #                  f'(wlan.supported_rates == 0x98)) && (wlan.supported_rates == 0xb0)'
        #
        # # Probe Response & Basic data rates
        # packet_filter3 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {ap_bssid} ' \
        #                  f'and wlan.fc.type_subtype == 0x0005 and (((wlan.supported_rates == 0x82) && ' \
        #                  f'(wlan.supported_rates == 0x84)) && (wlan.supported_rates == 0x30))'
        #
        # # Probe req & basic data rates
        # packet_filter4 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.sa == {dut_mac_address} ' \
        #                  f'and wlan.fc.type_subtype == 0x0004 or ((((wlan.supported_rates == 0x82) && ' \
        #                  f'(wlan.supported_rates == 0x84)) && (wlan.supported_rates == 0x8c)) && ' \
        #                  f'(wlan.supported_rates == 0x98)) && (wlan.supported_rates == 0xb0)'


        packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_basic_data_rates_assoc_req')

        packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_bssid,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_basic_data_rates_assoc_req')

        packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                            wlan_radio_channel=wifi_access_point.
                                                                            interfaces.wifi.channel,
                                                                            filter_name='mgmt_basic_data_rates_probe_req')

        socket_obj.socket_data_transfer()
        wifi_dut.interfaces.wifi.leave()

        wifi_sniffer.interfaces.capture.stop_capture()
        logger().info("Stop Sniffer finally")
        result1 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)
        result2 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)
        result3 = wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)

        if result1['packet_count'] is False or result2['packet_count'] is False or result3['packet_count'] is False:
            logger().info(
                f"Expected packet validation failed, Assoc req = {result1}, Probe req = {result3}, Probe res = {result2}")
            assert False
        else:
            logger().info(
                f"Assoc req = {result1['packet_count']}, Probe res = {result2['packet_count']}, Probe req = {result3['packet_count']}")
            logger().info("Sniffer validation Passed")
            assert True
    except Exception as e:
        logger().info(f"\n\n **** Got exception: {str(e)} ****\n\n")
        assert False, "Failed"
    else:
        logger().info("\n\n **** Test case is passed successfully..! ****\n\n")
    finally:
        socket_obj.clean_up_method()

@pytest.mark.skip
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
def test_wifi_sdk_data_rates_with_diff_rssi_values_c19630(wifi_sniffer, wifi_access_point, wifi_dut, rf_attenuator, utf_constants, request):
    data = "Thisisfromclient"
    ping_count = utf_constants.get("ping_count")
    time_period = utf_constants.get("time_period")
    test_name = request.node.name
    set_rssi = 0

    socket_obj = SocketDataTransfer(wifi_dut=wifi_dut, wifi_access_point=wifi_access_point, time_period=time_period,
                                    data=data)

    rejoin_value = 150
    time_period = 180
    packet_filter6 = '    Data Rate:'

    '''Verify data rate functionality of STA DUT using AUTO RATE as data rate with AP OPEN mode'''

    wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
    wifi_sniffer.interfaces.capture.start_capture(capture_file=test_name)
    wifi_dut.interfaces.wifi.wifi_set_advanced_client_config(max_retry_attempts=rejoin_value, scan_interval=4,
                                                             beacon_missed_count=40, first_time_retry_enable=0)

    scan_results = wifi_dut.interfaces.wifi.scan(ssid=wifi_access_point.interfaces.wifi.ssid)
    logger().info(f'\n\n{scan_results[0]}\n')
    my_str = str(scan_results[0])
    current_rssi = abs(int(my_str.strip('()').split(' ')[5]))
    logger().info(f'Current RSSI = {current_rssi}')
    logger().info(f'Make RSSI -35 for ideal condition')
    if current_rssi < 35:
        set_rssi = 35 - current_rssi
    elif current_rssi > 35:
        set_rssi = current_rssi - 35
    elif current_rssi == 35:
        set_rssi = 35

    logger().info(f'SET RSSI value = {set_rssi}')

    # set data rate in Auto mode
    wifi_dut.interfaces.wifi.set_transmit_rate(rate_protocol="auto", data_rate="auto")
    dut_ip = socket_obj.wifi_join(ping_count=ping_count)
    logger().info(f"DUT IP_Address: {dut_ip}")

    ap_bssid = wifi_access_point.interfaces.wifi.bssid
    logger().info(f'AP BSSID = {ap_bssid}')

    dut_mac_address = wifi_dut.interfaces.wifi.get_mac_address()
    logger().info(f"DUT MAC_Address: {dut_mac_address}")

    # logger().info(f"*****Enable Max PSP in DUT******")
    # wifi_dut.interfaces.wifi.power_save(2, 1)
    # wifi_dut.interfaces.wifi.bt_power_save(
    #     power_save_mode=RS9116PowerSaveModes.PowerSaveMode2
    # )
    #
    # # Broadcast probe request packet
    # packet_filter1 = f'(wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} ' \
    #                  f'and wlan.fc.type_subtype == 0x0004 and wlan.da == ff:ff:ff:ff:ff:ff) and (wlan.sa == ' \
    #                  f'{dut_mac_address})'
    #
    # # Association req/response packet
    # packet_filter2 = f'wlan_radio.channel == {wifi_access_point.interfaces.wifi.channel} and wlan.addr == {ap_bssid} ' \
    #                  f'or wlan.fc.type_subtype == 0 or wlan.fc.type_subtype == 1 or wlan.addr == {dut_mac_address}'
    #
    # # Power save mode with pmt bit 1
    # packet_filter3 = f'(wlan.fc.pwrmgt == 1) && ((wlan.fc.type_subtype == 0x0024) && (wlan.sa == {dut_mac_address}) && ' \
    #                  f'(wlan.da == {ap_bssid}))'
    #
    # # Data packets from DUT side
    # packet_filter5 = f'wlan.ta == {dut_mac_address} && wlan.ra == {ap_bssid} && (wlan.fc.type_subtype == 0x0028)'

    packet_filter1 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        wlan_radio_channel=wifi_access_point.
                                                                        interfaces.wifi.channel,
                                                                        filter_name='probe_request')
    packet_filter2 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        da_mac_address=ap_bssid,
                                                                        filter_name='association_request')
    packet_filter3 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=ap_bssid,
                                                                        da_mac_address=dut_mac_address,
                                                                        filter_name='association_response')
    packet_filter4 = wifi_sniffer.interfaces.capture.get_sniffer_filter(sa_mac_address=dut_mac_address,
                                                                        da_mac_address=ap_bssid,
                                                                        filter_name='power_mgmt_bit')
    packet_filter5 = wifi_sniffer.interfaces.capture.get_sniffer_filter(ta_mac_address=dut_mac_address,
                                                                        ra_mac_address=ap_bssid,
                                                                        filter_name='data_packets')

    socket_obj.socket_data_transfer()

    wifi_sniffer.interfaces.capture.stop_capture()
    logger().info("Stop Sniffer finally")
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter1)['packet_count'], \
        'Unable to find Broadcast probe request packet'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter2)['packet_count'], \
        'Unable to find Association req packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter3)['packet_count'], \
        'Unable to find Association response packets'
    assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter4)['packet_count'], \
        'Unable to find Power save mode with pmt bit 1'


    if connect_status is False:
        logger().info("Unable to connect with Server")

        assert connect_status
    else:
        sw = Stopwatch()
        db_value = 10
        att_channel = 1
        attenuation_data_rates_dict = dict()

        file_name = 'attenuation_' + str(db_value)
        logger().info('***** Set the attenuator *****')
        # ideal_rssi = set_rssi + current_rssi
        # set_db_value = int(ideal_rssi) + db_value
        ideal_rssi = 10
        set_db_value = int(ideal_rssi) + db_value
        logger().info(f'\n\n Set the ideal RSSI = {ideal_rssi}\n')
        wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, ideal_rssi)

        while sw.elapsed_sec < time_period:

            time.sleep(10)

            wifi_sniffer.interfaces.capture.configure_interface(channel=wifi_access_point.interfaces.wifi.channel)
            wifi_sniffer.interfaces.capture.start_capture(capture_file=file_name)
            logger().info(f'current time = {sw.elapsed_sec}, end time = {time_period}')
            send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
            logger().info(f'SEND-RESPONSE = {send_response}')

            logger().info(f'\n\n set_db_value = {set_db_value}\n')
            wifi_dut.interfaces.wifi.set_attenuator(rf_attenuator, att_channel, set_db_value)
            time.sleep(10)
            sw1 = Stopwatch()
            while sw1.elapsed_sec < 30:
                logger().info(f'\n\n current time = {sw.elapsed_sec}\n')
                send_response = wifi_dut.interfaces.wifi.send(tcp_socket_id, send_bytes)
                logger().info(f'\n\n SEND-RESPONSE = {send_response}\n')
            wifi_sniffer.interfaces.capture.stop_capture()

            assert wifi_sniffer.interfaces.capture.sniffer_validation(packet_filter1=packet_filter5,
                                                                      packet_filter2=packet_filter6)['packet_count'], \
                'Unable to find data packets'

            attenuation_data_rates_dict[eval('set_db_value')] = tcp_socket_obj.verify_data_rates()
            logger().info(f'Attenuation and Data Rates value = {attenuation_data_rates_dict}')
            set_db_value = set_db_value + 10

        logger().info(f'Attenuation and Data Rates value = {attenuation_data_rates_dict}')
        wifi_dut.interfaces.wifi.leave()
